/*
  Author: Tomas M <tomas@slax.org>
  License: GNU GPL

  Dynamic size loop filesystem, provides really big file which is allocated on disk only as needed
  You can then make a filesystem on it and mount it using -o loop,sync

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#define _ATFILE_SOURCE 1
#define _GNU_SOURCE 1
#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <wait.h>

#define LOG_TAG "DYNFILEFS"
#include <lib/log.h>

#include <util.h>

#define DYNFILE_MAGIC "DynfileFS2"
typedef struct {
    char magic[24];
    uint64_t virtual_size;
} dynfile_header_t;

static const char *dynfilefs_path = "/loop.fs";
static const char *save_path = "changes.dat";
static dynfile_header_t header;
off_t first_index = 0;
off_t zero = 0;

static pthread_mutex_t dynfilefs_mutex;

#define DATA_BLOCK_SIZE 4096
#define NUM_INDEXED_BLOCKS 16384

FILE * fp;
static const char empty[DATA_BLOCK_SIZE];

#include "dyfslib.c"

static int with_unlock(int err)
{
   pthread_mutex_unlock(&dynfilefs_mutex);
   return err;
}

static int dynfilefs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	(void) path;
	(void) isdatasync;
	(void) fi;
	fflush(fp);
	return 0;
}


static int dynfilefs_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, dynfilefs_path) == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = header.virtual_size;
	} else
		res = -ENOENT;

	return res;
}

static int dynfilefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, dynfilefs_path + 1, NULL, 0);

	return 0;
}

static int dynfilefs_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, dynfilefs_path) != 0)
		return -ENOENT;

        (void) fi;
	return 0;
}

static int dynfilefs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
    if (strcmp(path, dynfilefs_path) != 0) return -ENOENT;

    off_t tot = 0;
    off_t data_offset;
    off_t len = 0;
    off_t rd;
    (void) fi;

    pthread_mutex_lock(&dynfilefs_mutex);

    while (tot < size)
    {
        data_offset = get_data_offset(offset);
        if (data_offset != 0)
        {
           rd = DATA_BLOCK_SIZE - (offset % DATA_BLOCK_SIZE);
           if (tot + rd > size) rd = size - tot;
           fseeko(fp, data_offset + (offset % DATA_BLOCK_SIZE), SEEK_SET);
           len = fread(buf, 1, rd, fp);
        }

        if (len < 0) return with_unlock(-errno);

        if (len == 0 || data_offset == 0)
        {
           len = DATA_BLOCK_SIZE - (offset % DATA_BLOCK_SIZE);
           memset(buf, 0, len);
        }
        tot += len;
        buf += len;
        offset += len;
    }

    pthread_mutex_unlock(&dynfilefs_mutex);
    return tot;
}


static int dynfilefs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
    if(strcmp(path, dynfilefs_path) != 0) return -ENOENT;

    off_t tot = 0;
    off_t data_offset;
    off_t len;
    off_t wr;
    (void) fi;

    pthread_mutex_lock(&dynfilefs_mutex);

    while (tot < size)
    {
       data_offset = get_data_offset(offset);
       wr = DATA_BLOCK_SIZE - (offset % DATA_BLOCK_SIZE);
       if (tot + wr > size) wr = size - tot;

       // skip writing empty blocks if not already exist
       if (!memcmp(&empty, buf, wr) && data_offset == 0)
       {
          len = wr;
       }
       else // write block
       {
          if (data_offset == 0) data_offset = create_data_offset(offset);
          if (data_offset == 0) return with_unlock(-ENOSPC); // write error, not enough free space
          fseeko(fp, data_offset + (offset % DATA_BLOCK_SIZE), SEEK_SET);
          len = fwrite(buf, 1, wr, fp);
          if (len < 0) return with_unlock(-errno);
       }
       tot += len;
       buf += len;
       offset += len;
    }

    pthread_mutex_unlock(&dynfilefs_mutex);
    return tot;
}


static int dynfilefs_flush(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	(void) fi;
	fflush(fp);
	return 0;
}

static struct fuse_operations dynfilefs_oper = {
	.getattr	= dynfilefs_getattr,
	.readdir	= dynfilefs_readdir,
	.open		= dynfilefs_open,
	.read		= dynfilefs_read,
	.write		= dynfilefs_write,
	.fsync		= dynfilefs_fsync,
	.flush		= dynfilefs_flush,
};

int dynfilefs_mount(const char* storage_file, unsigned long blocks, const char* mountpoint)
{
    int ret;
    char *argv[64];
    int argc = 0;
    char cmpmagic[24];

    memset(cmpmagic, 0, sizeof(cmpmagic));
    memcpy(cmpmagic, DYNFILE_MAGIC, strlen(DYNFILE_MAGIC));

    save_path = storage_file;

    if (blocks == 0)
    {
       return -EINVAL;
    }

    // build fuse arguments
    argv[argc++] = strdup("dynfilefs");
    argv[argc++] = strdup(mountpoint);

    if(!argv[0] || !argv[1])
        return -ENOMEM;

    // open save data file
    fp = fopen(save_path, "r+");
    if (fp == NULL)
    {
       // create empty dataset
       fp = fopen(save_path, "w+");
       if (fp == NULL)
       {
          return EFIVARS_LOG_TRACE(14, "cannot open %s for writing\n", save_path);
       }

       // build header
       header.virtual_size = blocks*512llu;
       memcpy(header.magic, cmpmagic, sizeof(header.magic));

       // write header
       ret = fwrite(&header,sizeof(header),1,fp);
       if (ret < 0)
       {
          return EFIVARS_LOG_TRACE(15, "cannot write to %s\n", save_path);
       }
       fseeko(fp, sizeof(header) + NUM_INDEXED_BLOCKS*sizeof(zero)*2, SEEK_SET);
       ret = fwrite(&zero,sizeof(zero),1,fp);
    }

    if (fp == NULL)
    {
       return EFIVARS_LOG_TRACE(16, "cannot open %s for writing\n", save_path);
    }

    fseeko(fp, 0, SEEK_SET);

    // read header
    ret = fread(&header, sizeof(header), 1, fp);
    if(ret < 0) {
       return EFIVARS_LOG_TRACE(-1, "cannot read header of %s\n", save_path);
    }

    // check magic
    if(memcmp(header.magic, cmpmagic, sizeof(cmpmagic))) {
       return EFIVARS_LOG_TRACE(-1, "invalid magic in %s\n", save_path);
    }

    // first index is always right after the header. Get the position
    first_index = sizeof(header);

    // empty block is needed for comparison. Blocks full of null bytes are not stored
    memset((void*)&empty, 0, sizeof(empty));

    // create mountpoint
    if(!util_exists(mountpoint, false)) {
        ret = util_mkdir(mountpoint);
        if(ret) {
            return ret;
        }
    }

    pid_t pid;

    pid = fork();
    if (!pid) {
        ret = fuse_main(argc, argv, &dynfilefs_oper, NULL);
    }
    else {
        waitpid(pid, &ret, 0);
    }

    // cleanup
    free(argv[0]);
    free(argv[1]);

    return ret;
}
