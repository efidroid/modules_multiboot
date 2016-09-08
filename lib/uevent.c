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

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <lib/uevent.h>

#include <common.h>
#include <util.h>

#define LOG_TAG "UEVENT"
#include <lib/log.h>

#define UEVENT_PATH_BLOCK_DEVICES MBPATH_SYS "/class/block"

/*
 * Source: http://stackoverflow.com/questions/122616/how-do-i-trim-leading-trailing-whitespace-in-a-standard-way
 */
static char *copy_trim(const char *s)
{
    int start, end;
    for (start = 0; s[start] && isspace(s[start]); ++start);
    if (s[start] == '\0')
        return safe_strdup("");
    for (end = strlen(s); end > 0 && isspace(s[end - 1]); --end);
    return strndup(s + start, end - start);
}

static int getint(const char *s)
{
    char *endptr;

    long ret = strtol(s, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return -1;
    }

    return ret;
}

static uevent_block_t *get_blockinfo_by_filename(list_node_t *info, const char *filename)
{
    uevent_block_t *event;
    list_for_every_entry(info, event, uevent_block_t, node) {
        if (!strcmp(event->filename, filename))
            return event;
    }

    return NULL;
}

static int add_uevent_entry(list_node_t *info, const char *filename)
{
    FILE *fp;
    char line[128];

    // open file
    fp = fopen(filename, "r");
    if (fp == NULL) {
        LOGE("Can't open file %s: %s\n", filename, strerror(errno));
        return -errno;
    }

    // allocate memory
    uevent_block_t *entry = safe_calloc(1, sizeof(uevent_block_t));
    entry->filename = safe_strdup(filename);

    // parse file
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *name = copy_trim(strtok(line, "="));
        char *value = copy_trim(strtok(NULL, "="));

        if (!name || !value)
            continue;

        if (!strcmp(name, "MAJOR")) {
            entry->major = getint(value);
        } else if (!strcmp(name, "MINOR")) {
            entry->minor = getint(value);
        } else if (!strcmp(name, "PARTN")) {
            entry->partn = getint(value);
        } else if (!strcmp(name, "DEVNAME")) {
            entry->devname = safe_strdup(value);
        } else if (!strcmp(name, "PARTNAME")) {
            entry->partname = safe_strdup(value);
        } else if (!strcmp(name, "DEVTYPE")) {
            if (!strcmp(value, "disk"))
                entry->type = UEVENT_BLOCK_TYPE_DISK;
            else if (!strcmp(value, "partition"))
                entry->type = UEVENT_BLOCK_TYPE_PARTITION;
            else
                entry->type = UEVENT_BLOCK_TYPE_UNKNOWN;
        }
    }

    list_add_tail(info, &entry->node);

    // close file
    if (fclose(fp)) {
        LOGW("Can't close %s: %s\n", filename, strerror(errno));
    }

    return 0;
}

static int get_block_devices_internal(list_node_t *info, int rescan)
{
    const char *path = UEVENT_PATH_BLOCK_DEVICES;
    char buf[PATH_MAX];

    DIR *d = opendir(path);
    if (!d) {
        LOGE("Can't open %s: %s\n", path, strerror(errno));
        free(info);
        return -1;
    }

    struct dirent *dt;
    while ((dt = readdir(d))) {
        if (dt->d_type != DT_LNK)
            continue;

        SAFE_SNPRINTF_RET(LOGE, -1, buf, ARRAY_SIZE(buf), "%s/%s/uevent", path, dt->d_name);

        // skip if this is a rescan and the item does already exist
        if (rescan && get_blockinfo_by_filename(info, buf))
            continue;

        add_uevent_entry(info, buf);
    }

    if (closedir(d)) {
        LOGW("Can't close %s: %s\n", path, strerror(errno));
    }

    return 0;
}

list_node_t *get_block_devices(void)
{
    list_node_t *info = safe_malloc(sizeof(list_node_t));
    list_initialize(info);

    int rc = get_block_devices_internal(info, 0);
    if (rc) {
        free(info);
        return NULL;
    }

    return info;
}

void add_new_block_devices(list_node_t *info)
{
    get_block_devices_internal(info, 1);
}

void free_block_devices(list_node_t *info)
{
    while (!list_is_empty(info)) {
        uevent_block_t *event = list_peek_tail_type(info, uevent_block_t, node);

        if (event->devname)
            free(event->devname);
        if (event->partname)
            free(event->partname);
        free(event);
    }

    free(info);
}

uevent_block_t *get_blockinfo_for_path(list_node_t *info, const char *path)
{
    char *search_name = NULL;
    bool use_name = false;
    const char *search_devname = NULL;
    uevent_block_t *ret = NULL;

    int mbpath_len = strlen(MBPATH_ROOT);
    if (!strncmp(path, MBPATH_ROOT, mbpath_len))
        path+=mbpath_len;

    if (strstr(path, "by-name") != NULL) {
        search_name = util_basename(path);
        if (!search_name) {
            return NULL;
        }
        use_name = true;
    } else {
        const char *prefix = "/dev/block/";
        if (strncmp(path, prefix, strlen(prefix))) {
            return NULL;
        }

        search_devname = path + strlen(prefix);
    }

    uevent_block_t *event;
    list_for_every_entry(info, event, uevent_block_t, node) {
        if (use_name && event->partname && !strcmp(event->partname, search_name)) {
            ret = event;
            break;
        } else if (!use_name && event->devname && !strcmp(event->devname, search_devname)) {
            ret = event;
            break;
        }
    }

    free(search_name);

    return ret;
}

uevent_block_t *get_blockinfo_for_partname(list_node_t *info, const char *partname)
{
    uevent_block_t *event;
    list_for_every_entry(info, event, uevent_block_t, node) {
        if (event->partname && !strcmp(event->partname, partname)) {
            return event;
        }
    }

    return NULL;
}

uevent_block_t *get_blockinfo_for_devname(list_node_t *info, const char *devname)
{
    uevent_block_t *event;
    list_for_every_entry(info, event, uevent_block_t, node) {
        if (event->partname && !strcmp(event->devname, devname)) {
            return event;
        }
    }

    return NULL;
}

char *uevent_realpath_prefix(list_node_t *info, const char *path, char *resolved_path, const char *prefix)
{
    uevent_block_t *bi = get_blockinfo_for_path(info, path);
    if (!bi)
        return NULL;

    SAFE_SNPRINTF_RET(LOGE, NULL, resolved_path, PATH_MAX, "%s/dev/block/%s", prefix, bi->devname);

    return resolved_path;
}

char *uevent_realpath(list_node_t *info, const char *path, char *resolved_path)
{
    return uevent_realpath_prefix(info, path, resolved_path, "");
}

int uevent_create_nodes(list_node_t *info, const char *path)
{
    char buf[PATH_MAX];
    char path_block[PATH_MAX];
    int rc;

    // build block device path
    SAFE_SNPRINTF_RET(LOGE, -1, path_block, sizeof(path_block), "%s/block", path);

    // create block directory
    if (!util_exists(path_block, 1)) {
        rc = util_mkdir(path_block);
        if (rc<0) {
            return rc;
        }
    }

    // create all block nodes
    uevent_block_t *bi;
    list_for_every_entry(info, bi, uevent_block_t, node) {
        // build node path
        SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), "%s/%s", path_block, bi->devname);

        // create node
        rc = mknod(buf, S_IFBLK | 0600, makedev(bi->major, bi->minor));
        if (rc<0 && errno!=EEXIST) {
            return rc;
        }
    }
    // build devzero path
    SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), "%s/zero", path);

    // create devzero node
    rc = mknod(buf, S_IFCHR | 0666, makedev(1, 5));
    if (rc<0 && errno!=EEXIST) {
        return rc;
    }

    // build devnull path
    SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), "%s/null", path);

    // create devnull node
    rc = mknod(buf, S_IFCHR | 0666, makedev(1, 3));
    if (rc<0 && errno!=EEXIST) {
        return rc;
    }

    return 0;
}

int uevent_mount(uevent_block_t *bi, const char *target,
                 const char *filesystemtype, unsigned long mountflags,
                 const void *data)
{
    char buf[PATH_MAX];

    // build dev name
    SAFE_SNPRINTF_RET(LOGE, -1, buf, sizeof(buf), MBPATH_DEV"/block/%s", bi->devname);

    // mount
    return util_mount(buf, target, filesystemtype, mountflags, data);
}
