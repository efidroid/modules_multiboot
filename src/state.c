#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <common.h>
#include <safe.h>
#include <lib/fs_mgr.h>

#define LOG_TAG "STATE"
#include <lib/log.h>

#define write_primitive(fd, v) write_data(fd, &(v), sizeof(v))
#define read_primitive(fd, v) read_data(fd, v, sizeof(*(v)))
#define write_ptr(fd, v) write_primitive(fd, v)
#define read_ptr(fd, v) read_primitive(fd, v)

typedef struct {
    list_node_t node;
    void *old;
    void *new;
    size_t size;
} registered_ptr_t;

typedef struct {
    list_node_t node;
    void *old;
    void **pnew;
} required_ptr_t;

static list_node_t ptr_registered;
static list_node_t ptr_required;

static void write_data(int fd, const void *value, size_t size)
{
    ssize_t num_bytes = write(fd, value, size);
    if (num_bytes<0 || (size_t)num_bytes != size) {
        MBABORT("%s: %s\n", __func__, strerror(errno));
    }
}

static void read_data(int fd, void *buf, size_t size)
{
    ssize_t num_bytes = read(fd, buf, size);
    if (num_bytes<0 || (size_t)num_bytes != size) {
        MBABORT("%s: %s\n", __func__, strerror(errno));
    }
}

static void write_str(int fd, const char *value)
{
    write_ptr(fd, value);
    if (value) {
        size_t len = strlen(value)+1;
        write_primitive(fd, len);
        write_data(fd, value, len);
    }
}

static void read_str(int fd, char **value)
{
    void *ptrval;
    size_t len;

    read_ptr(fd, &ptrval);
    if (ptrval) {
        read_primitive(fd, &len);

        void *nptr = safe_malloc(len);
        read_data(fd, nptr, len);

        *value = nptr;
    } else {
        *value = NULL;
    }
}

static void require_ptr(int fd, void **nptr)
{
    void *oldptr;

    read_ptr(fd, &oldptr);

    if (oldptr) {
        required_ptr_t *p = safe_malloc(sizeof(required_ptr_t));
        p->old = oldptr;
        p->pnew = nptr;

        list_add_tail(&ptr_required, &p->node);
    } else {
        *nptr = NULL;
    }
}

static void register_ptr(void *oldptr, void *newptr, size_t size)
{
    registered_ptr_t *p = safe_malloc(sizeof(registered_ptr_t));
    p->old = oldptr;
    p->new = newptr;
    p->size = size;

    list_add_tail(&ptr_registered, &p->node);
}

static void *oldptr2newptr(void *oldptr)
{
    registered_ptr_t *regp;
    list_for_every_entry(&ptr_registered, regp, registered_ptr_t, node) {
        if (oldptr>=regp->old && oldptr<regp->old+regp->size) {
            size_t offset = oldptr - regp->old;
            return regp->new + offset;
        }
    }

    MBABORT("%s: can't find memory for pointer %p\n", __func__, oldptr);
    return NULL;
}

static void update_required_ptrs(void)
{
    required_ptr_t *reqp;
    list_for_every_entry(&ptr_required, reqp, required_ptr_t, node) {
        void **pnew = reqp->pnew;

        *pnew = oldptr2newptr(reqp->old);
    }
}

static void write_fstab(int fd, struct fstab *fstab)
{
    int i;

    write_ptr(fd, fstab);
    if (!fstab) return;

    write_primitive(fd, fstab->num_entries);
    write_ptr(fd, fstab->recs);
    write_str(fd, fstab->fstab_filename);

    if (fstab->recs) {
        for (i=0; i<fstab->num_entries; i++) {
            struct fstab_rec *rec = &fstab->recs[i];

            write_str(fd, rec->blk_device);
            write_str(fd, rec->mount_point);
            write_str(fd, rec->fs_type);
            write_primitive(fd, rec->flags);
            write_str(fd, rec->fs_options);
            write_primitive(fd, rec->fs_mgr_flags);
            write_str(fd, rec->mnt_flags_orig);
            write_str(fd, rec->fs_mgr_flags_orig);
            write_str(fd, rec->key_loc);
            write_str(fd, rec->verity_loc);
            write_primitive(fd, rec->length);
            write_str(fd, rec->label);
            write_primitive(fd, rec->partnum);
            write_primitive(fd, rec->swap_prio);
            write_primitive(fd, rec->zram_size);
            write_primitive(fd, rec->zram_streams);
            write_str(fd, rec->esp);
        }
    }
}

static void read_fstab(int fd, struct fstab **pfstab)
{
    int i;
    void *oldptr_fstab;
    void *oldptr_recs;

    read_ptr(fd, &oldptr_fstab);
    if (!oldptr_fstab) {
        *pfstab = NULL;
        return;
    }

    struct fstab *fstab = safe_malloc(sizeof(struct fstab));
    register_ptr(oldptr_fstab, fstab, sizeof(*fstab));

    read_primitive(fd, &fstab->num_entries);
    read_ptr(fd, &oldptr_recs);
    read_str(fd, &fstab->fstab_filename);

    if (oldptr_recs) {
        fstab->recs = safe_calloc(fstab->num_entries, sizeof(struct fstab_rec));
        register_ptr(oldptr_recs, fstab->recs, fstab->num_entries*sizeof(struct fstab_rec));

        for (i=0; i<fstab->num_entries; i++) {
            struct fstab_rec *rec = &fstab->recs[i];

            read_str(fd, &rec->blk_device);
            read_str(fd, &rec->mount_point);
            read_str(fd, &rec->fs_type);
            read_primitive(fd, &rec->flags);
            read_str(fd, &rec->fs_options);
            read_primitive(fd, &rec->fs_mgr_flags);
            read_str(fd, &rec->mnt_flags_orig);
            read_str(fd, &rec->fs_mgr_flags_orig);
            read_str(fd, &rec->key_loc);
            read_str(fd, &rec->verity_loc);
            read_primitive(fd, &rec->length);
            read_str(fd, &rec->label);
            read_primitive(fd, &rec->partnum);
            read_primitive(fd, &rec->swap_prio);
            read_primitive(fd, &rec->zram_size);
            read_primitive(fd, &rec->zram_streams);
            read_str(fd, &rec->esp);
        }
    } else {
        fstab->recs = NULL;
    }

    *pfstab = fstab;
}

static void write_blockinfo(int fd, list_node_t *blockinfo)
{
    write_ptr(fd, blockinfo);
    if (!blockinfo) return;

    size_t listlen = list_length(blockinfo);
    write_primitive(fd, listlen);

    uevent_block_t *block;
    list_for_every_entry(blockinfo, block, uevent_block_t, node) {
        write_ptr(fd, block);

        write_str(fd, block->filename);
        write_primitive(fd, block->major);
        write_primitive(fd, block->minor);
        write_primitive(fd, block->partn);
        write_str(fd, block->devname);
        write_str(fd, block->partname);
        write_primitive(fd, block->type);
    }
}

static void read_blockinfo(int fd, list_node_t **pblockinfo)
{
    uint32_t i;
    void *oldptr;
    size_t listlen;

    read_ptr(fd, &oldptr);
    if (!oldptr) {
        *pblockinfo = NULL;
        return;
    }
    list_node_t *blockinfo = safe_calloc(sizeof(list_node_t), 1);
    register_ptr(oldptr, blockinfo, sizeof(*blockinfo));
    list_initialize(blockinfo);

    read_primitive(fd, &listlen);
    for (i=0; i<listlen; i++) {
        void *oldptr_block;

        read_ptr(fd, &oldptr_block);
        if (!oldptr_block) {
            MBABORT("%s: NULL block\n", __func__);
            return;
        }
        uevent_block_t *block = safe_calloc(sizeof(uevent_block_t), 1);
        register_ptr(oldptr_block, block, sizeof(*block));

        read_str(fd, &block->filename);
        read_primitive(fd, &block->major);
        read_primitive(fd, &block->minor);
        read_primitive(fd, &block->partn);
        read_str(fd, &block->devname);
        read_str(fd, &block->partname);
        read_primitive(fd, &block->type);

        list_add_tail(blockinfo, &block->node);
    }
}

static void write_replacements(int fd, list_node_t *replacements)
{
    write_ptr(fd, replacements);
    if (!replacements) return;

    size_t listlen = list_length(replacements);
    write_primitive(fd, listlen);

    part_replacement_t *replacement;
    list_for_every_entry(replacements, replacement, part_replacement_t, node) {
        write_ptr(fd, replacement);

        write_ptr(fd, replacement->uevent_block);
        write_primitive(fd, replacement->mountmode);
        write_primitive(fd, replacement->iomode);
        write_str(fd, replacement->bindsource);
        write_primitive(fd, replacement->losetup_done);
        write_str(fd, replacement->loopdevice);
        write_str(fd, replacement->loopfile);
        write_str(fd, replacement->loop_sync_target);
    }
}

static void read_replacements(int fd, list_node_t *replacements)
{
    uint32_t i;
    size_t listlen;
    void *oldptr_replacements;

    read_ptr(fd, &oldptr_replacements);
    if (!replacements) {
        MBABORT("%s: NULL replacements\n", __func__);
        return;
    }
    register_ptr(oldptr_replacements, replacements, sizeof(*replacements));
    list_initialize(replacements);

    read_primitive(fd, &listlen);
    for (i=0; i<listlen; i++) {
        void *oldptr_replacement;

        read_ptr(fd, &oldptr_replacement);
        if (!oldptr_replacement) {
            MBABORT("%s: NULL replacement\n", __func__);
            return;
        }
        part_replacement_t *replacement = safe_calloc(sizeof(part_replacement_t), 1);
        register_ptr(oldptr_replacement, replacement, sizeof(*replacement));

        pthread_mutex_init(&replacement->lock, NULL);
        require_ptr(fd, (void **)&replacement->uevent_block);
        read_primitive(fd, &replacement->mountmode);
        read_primitive(fd, &replacement->iomode);
        read_str(fd, &replacement->bindsource);
        read_primitive(fd, &replacement->losetup_done);
        read_str(fd, &replacement->loopdevice);
        read_str(fd, &replacement->loopfile);
        read_str(fd, &replacement->loop_sync_target);

        list_add_tail(replacements, &replacement->node);
    }
}

static void write_multiboot_partitions(int fd, multiboot_partition_t *mbparts, uint32_t num_mbparts)
{
    uint32_t i;

    for (i=0; i<num_mbparts; i++) {
        multiboot_partition_t *part = &mbparts[i];

        write_str(fd, part->name);
        write_str(fd, part->path);
        write_primitive(fd, part->type);
        write_ptr(fd, part->uevent_block);
    }
}

static void read_multiboot_partitions(int fd, multiboot_partition_t *mbparts, uint32_t num_mbparts)
{
    uint32_t i;

    for (i=0; i<num_mbparts; i++) {
        multiboot_partition_t *part = &mbparts[i];

        read_str(fd, &part->name);
        read_str(fd, &part->path);
        read_primitive(fd, &part->type);
        require_ptr(fd, (void **)&part->uevent_block);
    }
}


int state_save(void)
{
    multiboot_data_t *multiboot_data = multiboot_get_data();

    // open state file
    int fd = open(MBPATH_STATEFILE, O_WRONLY|O_TRUNC|O_CREAT, 0700);
    if (fd<0) {
        return -1;
    }

    write_primitive(fd, multiboot_data->is_multiboot);
    write_primitive(fd, multiboot_data->is_recovery);
    write_ptr(fd, multiboot_data->esp);
    write_ptr(fd, multiboot_data->espdev);
    write_fstab(fd, multiboot_data->mbfstab);
    write_blockinfo(fd, multiboot_data->blockinfo);
    write_str(fd, multiboot_data->hwname);
    write_str(fd, multiboot_data->slot_suffix);
    write_fstab(fd, multiboot_data->romfstab);
    write_str(fd, multiboot_data->romfstabpath);
    write_replacements(fd, &multiboot_data->replacements);
    write_str(fd, multiboot_data->guid);
    write_str(fd, multiboot_data->path);
    write_str(fd, multiboot_data->pttype);
    write_ptr(fd, multiboot_data->bootdev);
    write_primitive(fd, multiboot_data->bootdev_supports_bindmount);

    write_primitive(fd, multiboot_data->num_mbparts);
    write_ptr(fd, multiboot_data->mbparts);
    if (multiboot_data->mbparts) {
        write_multiboot_partitions(fd, multiboot_data->mbparts, multiboot_data->num_mbparts);
    }

    write_primitive(fd, multiboot_data->native_data_layout_version);
    write_str(fd, multiboot_data->datamedia_source);
    write_str(fd, multiboot_data->datamedia_target);


    // close state file
    close(fd);

    return 0;
}

int state_restore(void)
{
    multiboot_data_t *multiboot_data = multiboot_get_data();
    void *oldptr_mbparts;

    // open state file
    int fd = open(MBPATH_STATEFILE, O_RDONLY);
    if (fd<0) {
        return -1;
    }

    pthread_mutex_init(&multiboot_data->lock, NULL);

    list_initialize(&ptr_registered);
    list_initialize(&ptr_required);

    read_primitive(fd, &multiboot_data->is_multiboot);
    read_primitive(fd, &multiboot_data->is_recovery);
    require_ptr(fd, (void **)&multiboot_data->esp);
    require_ptr(fd, (void **)&multiboot_data->espdev);
    read_fstab(fd, &multiboot_data->mbfstab);
    read_blockinfo(fd, &multiboot_data->blockinfo);
    read_str(fd, &multiboot_data->hwname);
    read_str(fd, &multiboot_data->slot_suffix);
    read_fstab(fd, &multiboot_data->romfstab);
    read_str(fd, &multiboot_data->romfstabpath);
    read_replacements(fd, &multiboot_data->replacements);
    read_str(fd, &multiboot_data->guid);
    read_str(fd, &multiboot_data->path);
    read_str(fd, &multiboot_data->pttype);
    require_ptr(fd, (void **)&multiboot_data->bootdev);
    read_primitive(fd, &multiboot_data->bootdev_supports_bindmount);

    read_primitive(fd, &multiboot_data->num_mbparts);
    read_ptr(fd, &oldptr_mbparts);
    if (oldptr_mbparts) {
        multiboot_data->mbparts = safe_calloc(multiboot_data->num_mbparts, sizeof(multiboot_partition_t));
        register_ptr(oldptr_mbparts, multiboot_data->mbparts, multiboot_data->num_mbparts*sizeof(multiboot_partition_t));
        read_multiboot_partitions(fd, multiboot_data->mbparts, multiboot_data->num_mbparts);
    }

    read_primitive(fd, &multiboot_data->native_data_layout_version);
    read_str(fd, (char **)&multiboot_data->datamedia_source);
    read_str(fd, (char **)&multiboot_data->datamedia_target);

    update_required_ptrs();

    // close state file
    close(fd);

    return 0;
}
