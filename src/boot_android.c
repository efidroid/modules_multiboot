/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>

#include <lib/mounts.h>

#include <util.h>
#include <common.h>

#define LOG_TAG "BOOT_ANDROID"
#include <lib/log.h>

typedef struct {
    list_node_t node;

    struct fstab_rec *rec;
    part_replacement_t *replacement;
} remount_entry_t;

static multiboot_data_t *multiboot_data = NULL;
static list_node_t remount_entries = LIST_INITIAL_VALUE(remount_entries);

#define MBABORT_IF_MB(fmt, ...) do { \
    if(multiboot_data->is_multiboot) \
        MBABORT(fmt, ##__VA_ARGS__); \
    else \
        LOGE(fmt, ##__VA_ARGS__); \
}while(0)

static void handle_on_early_init(void)
{
    int rc;
    char buf[PATH_MAX];
    char buf2[PATH_MAX];

    part_replacement_t *replacement;
    list_for_every_entry(&multiboot_data->replacements, replacement, part_replacement_t, node) {
        struct stat sb_orig;
        struct stat sb_loop;

        // build path to dev node
        rc = snprintf(buf, sizeof(buf), "/dev/block/%s", replacement->uevent_block->devname);
        if (SNPRINTF_ERROR(rc, sizeof(buf))) {
            MBABORT_IF_MB("Can't build path for %s\n", replacement->uevent_block->devname);
            goto finish;
        }
        char *blk_device = buf;

        // stat original device
        rc = stat(blk_device, &sb_orig);
        if (rc) {
            MBABORT_IF_MB("Can't stat device at %s\n", blk_device);
            goto finish;
        }

        LOGD("replace %s with %s\n", blk_device, replacement->loopdevice);

        // stat loop device
        rc = stat(replacement->loopdevice, &sb_loop);
        if (rc) {
            MBABORT_IF_MB("Can't stat device at %s\n", replacement->loopdevice);
            goto finish;
        }

        // create path for backup node
        rc = snprintf(buf2, sizeof(buf2), "%s/replacement_backup_%s", MBPATH_DEV, replacement->uevent_block->devname);
        if (SNPRINTF_ERROR(rc, sizeof(buf2))) {
            MBABORT_IF_MB("Can't build name for backup node\n");
            goto finish;
        }

        // create backup node
        rc = mknod(buf2, S_IRUSR | S_IWUSR | S_IFBLK, makedev(major(sb_orig.st_rdev), minor(sb_orig.st_rdev)));
        if (rc) {
            MBABORT_IF_MB("Can't create backup node for device %s\n", buf2);
            goto finish;
        }

        // delete original node
        if (util_exists(blk_device, false)) {
            rc = unlink(blk_device);
            if (rc) {
                MBABORT_IF_MB("Can't delete %s\n", blk_device);
                goto finish;
            }
        }

        // create new node
        rc = mknod(blk_device, sb_orig.st_mode, makedev(major(sb_loop.st_rdev), minor(sb_loop.st_rdev)));
        if (rc) {
            MBABORT_IF_MB("Can't create replacement node at %s\n", blk_device);
            goto finish;
        }
    }

finish:
    if (multiboot_data->is_multiboot && rc)
        MBABORT("early-init failed: rc=%d errno=%d\n", rc, errno);

    return;
}

static void handle_on_post_fs_data(void)
{
    int rc;
    mounts_state_t mounts_state = LIST_INITIAL_VALUE(mounts_state);

    // scan mounted volumes
    rc = scan_mounted_volumes(&mounts_state);
    if (rc) {
        MBABORT_IF_MB("Can't scan mounted volumes: %s\n", strerror(errno));
        goto finish;
    }

    // find ESP volume
    const mounted_volume_t *volume = find_mounted_volume_by_majmin(&mounts_state, multiboot_data->espdev->major, multiboot_data->espdev->minor, 0);
    if (!volume) {
        LOGI("ESP is not mounted. do this now.\n");

        // mount ESP to our dir
        rc = util_mount_esp(multiboot_data->is_multiboot);
        if (rc) {
            MBABORT_IF_MB("Can't mount ESP: %s\n", strerror(errno));
            goto finish;
        }
    } else {
        LOGI("bind-mount ESP to %s\n", MBPATH_ESP);

        // bind-mount ESP to our dir
        rc = util_mount(volume->mount_point, MBPATH_ESP, NULL, MS_BIND, NULL);
        if (rc) {
            MBABORT_IF_MB("can't bind-mount ESP to %s: %s\n", MBPATH_ESP, strerror(errno));
            goto finish;
        }
    }

    // free mount state
    free_mounts_state(&mounts_state);

    part_replacement_t *replacement;
    list_for_every_entry(&multiboot_data->replacements, replacement, part_replacement_t, node) {
        if (!replacement->losetup_done) {
            if (!replacement->loopfile) {
                MBABORT_IF_MB("loopfile required for %s\n", replacement->loopdevice);
                goto finish;
            }

            // setup loop device
            LOGD("losetup %s with %s\n", replacement->loopdevice, replacement->loopfile);
            rc = util_losetup(replacement->loopdevice, replacement->loopfile, false);
            if (rc) {
                MBABORT_IF_MB("Can't setup loop device at %s for %s\n", replacement->loopdevice, replacement->loopfile);
                goto finish;
            }
        }
    }

finish:
    if (multiboot_data->is_multiboot && rc)
        MBABORT("post-fs-data init failed: rc=%d errno=%d\n", rc, errno);
}

static void add_remount_entry(struct fstab_rec *rec, part_replacement_t *replacement)
{
    remount_entry_t *entry = safe_malloc(sizeof(remount_entry_t));
    entry->rec = rec;
    entry->replacement = replacement;
    list_add_tail(&remount_entries, &entry->node);
}

static void handle_on_post_fstab(void)
{
    remount_entry_t *entry;
    list_for_every_entry(&remount_entries, entry, remount_entry_t, node) {
        SAFE_MOUNT(entry->replacement->multiboot.partpath, entry->rec->mount_point, entry->rec->fs_type, MS_REMOUNT|MS_BIND|entry->rec->flags, entry->rec->fs_options);
    }
}

static volatile sig_atomic_t mbinit_usr_interrupt = 0;
static void mbinit_usr_handler(UNUSED int sig, siginfo_t *info, UNUSED void *vp)
{
    // ignore further signals
    if (mbinit_usr_interrupt)
        return;

    // get command
    char *cmd = util_get_file_contents(MBPATH_TRIGGER_CMD);
    unlink(MBPATH_TRIGGER_CMD);
    if (!cmd) goto finish;

    LOGI("TRIGGER: %s\n", cmd);

    if (!strcmp(cmd, "early-init")) {
        handle_on_early_init();
    } else if (!strcmp(cmd, "post-fs-data")) {
        handle_on_post_fs_data();
    } else if (!strcmp(cmd, "post-fstab")) {
        handle_on_post_fstab();
    }

    // cleanup
    free(cmd);

finish:
    // continue sender
    kill(info->si_pid, SIGUSR1);
}

static volatile sig_atomic_t init_usr_interrupt = 0;
static void init_usr_handler(UNUSED int sig, UNUSED siginfo_t *info, UNUSED void *vp)
{
    // stop waiting for signals
    init_usr_interrupt = 1;
}

#define CHECK_WRITE(fd, str) \
        len = strlen(str); \
        bytes_written = write(fd, str, len); \
        if(bytes_written!=(size_t)len) { \
            MBABORT("Can't write\n"); \
        }

static int fstab_append(int fd, const char *blk_device, const char *mount_point, const char *fs_type, const char *mnt_flags, const char *fs_mgr_flags)
{
    size_t bytes_written;
    size_t len;

    // allocate line buffer
    size_t linelen = strlen(blk_device) + strlen(mount_point) + strlen(fs_type) + strlen(mnt_flags) + strlen(fs_mgr_flags) + 6;
    char *line = safe_malloc(linelen);

    // build line
    SAFE_SNPRINTF_RET(MBABORT, -1, line, linelen, "%s %s %s %s %s\n", blk_device, mount_point, fs_type, mnt_flags, fs_mgr_flags);

    // write line
    CHECK_WRITE(fd, line);

    // free line
    free(line);

    return 0;
}

#define SKIP_WHITESPACE(x) while(isspace(*(x))) (x)++;
#define NEXT_WORD_INTERNAL(str, p) ((p)=strtok_r((str), " \t", &save_ptr))
#define FIRST_WORD(p) NEXT_WORD_INTERNAL((p), (p))
#define NEXT_WORD(p) NEXT_WORD_INTERNAL(NULL, (p))

static int process_file(FILE *fp_orig, FILE *fp_out)
{
    char line[PATH_MAX];
    char *save_ptr;
    char buf[PATH_MAX];
    const char *pcmd;

    while (fgets(line, sizeof(line), fp_orig)) {
        size_t len = strlen(line);
        pcmd = NULL;

        // skip incomplete lines
        if (len && (line[len - 1] != '\n')) {
            goto write_unmodified;
        }

        // skip over leading whitespace
        pcmd = line;
        SKIP_WHITESPACE(pcmd);

        // we want mount commands only
        if (strstr(pcmd, "mount")==pcmd && isspace(pcmd[5])) {
            /* mount <type> <device> <path> <flags ...> <options> */

            // create a copy, and keep a pointer to the start
            char *p_start = safe_strdup(pcmd);
            char *p = p_start;

            // remove newline
            p_start[strlen(p_start) - 1] = 0;

            // 'mount'
            if (!FIRST_WORD(p)) goto write_unmodified;

            // type
            if (!NEXT_WORD(p)) goto write_unmodified;
            char *type = safe_strdup(p);

            // device
            if (!NEXT_WORD(p)) goto write_unmodified;
            UNUSED char *device = safe_strdup(p);

            // path
            if (!NEXT_WORD(p)) goto write_unmodified;
            char *path = safe_strdup(p);

            // flags and options
            const char *rest = pcmd + (save_ptr-p_start);
            SKIP_WHITESPACE(rest);

            // get uevent block for this device
            uevent_block_t *uevent_block = get_blockinfo_for_path(multiboot_data->blockinfo, device);
            if (!uevent_block) goto write_unmodified;

            // get replacement for this device
            part_replacement_t *replacement = util_get_replacement(uevent_block->major, uevent_block->minor);
            if (!replacement) goto write_unmodified;
            multiboot_partition_t *part = replacement->multiboot.part;

            const char *blk_device;
            const char *mnt_flags = rest;
            // determine mount args
            if (part && part->type==MBPART_TYPE_BIND) {
                blk_device = replacement->multiboot.partpath;
                mnt_flags = "bind";
            } else {
                blk_device = replacement->loopdevice;
            }

            // write modified command
            fprintf(fp_out, "    mount %s %s %s %s\n", type, blk_device, path, mnt_flags);

            // remount to apply requested mount-flags
            if (part && part->type==MBPART_TYPE_BIND) {
                SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), "remount,bind,%s", rest);
                fprintf(fp_out, "    mount %s %s %s %s\n", type, blk_device, path, buf);
            }

            // bind mount datamedia
            if (!strcmp(path, "/data")) {
                SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), "%s%s", path, multiboot_data->datamedia_target);

                LOGI("bind-mount %s to %s\n", multiboot_data->datamedia_source, buf);
                fprintf(fp_out, "    mount %s %s %s %s\n", type, multiboot_data->datamedia_source, buf, "bind");
            }

            // next entry
            continue;
        }

        // write unmodified command
write_unmodified:
        fputs(line, fp_out);

        if (pcmd && strstr(pcmd, "mount_all")==pcmd && isspace(pcmd[9])) {
            fputs("\n"
                  // start mbtrigger
                  "    write "MBPATH_TRIGGER_CMD" post-fstab\n"
                  "    start mbtrigger\n"
                  "    wait "MBPATH_TRIGGER_WAIT_FILE"\n"

                  // mbtrigger cleanup
                  "    rm "MBPATH_TRIGGER_WAIT_FILE"\n"
                  , fp_out);
        }
    }

    return 0;
}

static int patch_rc_files(void)
{
    DIR *dp;
    struct dirent *ep;
    char buf[PATH_MAX];

    dp = opendir("/");
    if (dp != NULL) {
        while ((ep=readdir (dp))) {
            if (!strcmp(ep->d_name, ".") || !strcmp(ep->d_name, ".."))
                continue;

            if (strcmp(util_get_file_extension(ep->d_name), "rc"))
                continue;

            // rename original file
            SAFE_SNPRINTF_RET(MBABORT, -1, buf, sizeof(buf), "%s.orig", ep->d_name);
            rename(ep->d_name, buf);

            // open original file
            FILE *fp_orig = fopen(buf, "r");
            if (!fp_orig) MBABORT("can't open %s: %s\n", buf, strerror(errno));

            // open output file
            FILE *fp_out = fopen(ep->d_name, "w");
            if (!fp_out) MBABORT("can't open %s: %s\n", ep->d_name, strerror(errno));

            // process file
            LOGV("process: %s\n", ep->d_name);
            process_file(fp_orig, fp_out);

            // close files
            fclose(fp_out);
            fclose(fp_orig);

            // set permissions for patched file
            chmod(ep->d_name, 0750);

            // delete original file
            unlink(buf);
        }
        closedir (dp);
    } else {
        MBABORT("Can't open root directory: %s\n", strerror(errno));
    }

    return 0;
}

int boot_android(void)
{
    multiboot_data = multiboot_get_data();

    int rc;
    int i;
    char buf[PATH_MAX];

    // multiboot setup
    if (multiboot_data->is_multiboot) {
        // patch all rc files
        patch_rc_files();

        // open fstab for writing
        int fd = open(multiboot_data->romfstabpath, O_WRONLY|O_TRUNC);
        if (fd<0) {
            MBABORT("Can't open init.rc for writing\n");
        }

        // write entries
        struct fstab_rec *datarec = NULL;
        for (i=0; i<multiboot_data->romfstab->num_entries; i++) {
            struct fstab_rec *rec = &multiboot_data->romfstab->recs[i];
            const char *blk_device = rec->blk_device;
            const char *mnt_flags = rec->mnt_flags_orig;

            // get uevent block for this device
            uevent_block_t *uevent_block = get_blockinfo_for_path(multiboot_data->blockinfo, rec->blk_device);
            if (!uevent_block) goto write_entry;

            // get replacement for this device
            part_replacement_t *replacement = util_get_replacement(uevent_block->major, uevent_block->minor);
            if (!replacement) goto write_entry;
            multiboot_partition_t *part = replacement->multiboot.part;

            // determine mount args
            if (part && part->type==MBPART_TYPE_BIND) {
                blk_device = replacement->multiboot.partpath;
                mnt_flags = "bind";

                add_remount_entry(rec, replacement);
            } else {
                blk_device = replacement->loopdevice;
            }

            // write entry
write_entry:
            fstab_append(fd, blk_device, rec->mount_point, rec->fs_type, mnt_flags, rec->fs_mgr_flags_orig);

            // save rec for /data
            if (!strcmp(rec->mount_point, "/data")) {
                datarec = rec;
            }
        }

        // bind mount datamedia
        if (datarec) {
            SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), "%s%s", datarec->mount_point, multiboot_data->datamedia_target);

            LOGI("bind-mount %s to %s\n", multiboot_data->datamedia_source, buf);
            fstab_append(fd, multiboot_data->datamedia_source, buf, datarec->fs_type, "bind", "defaults");
        }

        // close file
        close(fd);
    }

    LOGI("Booting Android\n");
    pid_t pid = safe_fork();

    // parent
    if (pid) {
        // install usr handler
        util_setsighandler(SIGUSR1, init_usr_handler);

        // wait for mbinit to finish
        WAIT_FOR_SIGNAL(SIGUSR1, !init_usr_interrupt);

        return run_init(0);
    }

    // child
    else {
        // add trigger events
        SAFE_SNPRINTF_RET(LOGE, -1, buf, PATH_MAX, "\n\n"
                          "on early-init\n"
                          // wait for coldboot
                          "    wait /dev/.coldboot_done\n"
                          "\n"

                          // start mbtrigger
                          "    write "MBPATH_TRIGGER_CMD" early-init\n"
                          "    start mbtrigger\n"
                          "    wait "MBPATH_TRIGGER_WAIT_FILE"\n"

                          // mbtrigger cleanup
                          "    rm "MBPATH_TRIGGER_WAIT_FILE"\n"


                          "on post-fs-data\n"
                          // start mbtrigger
                          "    write "MBPATH_TRIGGER_CMD" post-fs-data\n"
                          "    start mbtrigger\n"
                          "    wait "MBPATH_TRIGGER_WAIT_FILE"\n"

                          // mbtrigger cleanup
                          "    rm "MBPATH_TRIGGER_WAIT_FILE"\n"
                          "\n"

                          // trigger service
                          "service mbtrigger "MBPATH_TRIGGER_BIN" %u\n"
                          "    disabled\n"
                          "    oneshot\n"
                          "\n"

                          , getpid()
                         );
        rc = util_append_string_to_file("/init.rc", buf);
        if (rc) return rc;

        // install trigger handler
        util_setsighandler(SIGUSR1, mbinit_usr_handler);

        // continue init
        kill(getppid(), SIGUSR1);

        // wait for trigger
        WAIT_FOR_SIGNAL(SIGUSR1, !mbinit_usr_interrupt);

        // we are not allowed to return
        exit(0);
    }
}
