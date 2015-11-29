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
		return strdup("");
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

static int add_uevent_entry(uevent_block_info_t *info, const char *filename)
{
	FILE *fp;
	char line[128];

	// open file
	fp = fopen(filename, "r");
	if (fp == NULL) {
		LOGE("Can't open file %s\n", filename);
		return -errno;
	}

	// allocate memory
	int index = info->num_entries++;
	info->entries = realloc(info->entries, info->num_entries * sizeof(info->entries[0]));
	memset(&info->entries[index], 0, sizeof(info->entries[0]));

	// parse file
	while (fgets(line, sizeof(line), fp) != NULL) {
		char *name = copy_trim(strtok(line, "="));
		char *value = copy_trim(strtok(NULL, "="));

		if (!name || !value)
			continue;

		if (!strcmp(name, "MAJOR")) {
			info->entries[index].major = getint(value);
		} else if (!strcmp(name, "MINOR")) {
			info->entries[index].minor = getint(value);
		} else if (!strcmp(name, "PARTN")) {
			info->entries[index].partn = getint(value);
		} else if (!strcmp(name, "DEVNAME")) {
			info->entries[index].devname = strdup(value);
		} else if (!strcmp(name, "PARTNAME")) {
			info->entries[index].partname = strdup(value);
		} else if (!strcmp(name, "DEVTYPE")) {
			if (!strcmp(value, "disk"))
				info->entries[index].type = UEVENT_BLOCK_TYPE_DISK;
			else if (!strcmp(value, "partition"))
				info->entries[index].type =
				    UEVENT_BLOCK_TYPE_PARTITION;
			else
				info->entries[index].type = UEVENT_BLOCK_TYPE_UNKNOWN;
		}
	}

	// close file
	if(fclose(fp)) {
		LOGW("Can't close %s: %s\n", filename, strerror(errno));
    }

	return 0;
}

uevent_block_info_t *get_block_devices(void)
{
	const char *path = UEVENT_PATH_BLOCK_DEVICES;
	char buf[PATH_MAX];
	uevent_block_info_t *info = malloc(sizeof(uevent_block_info_t));
	memset(info, 0, sizeof(info[0]));

	DIR *d = opendir(path);
	if (!d) {
		LOGE("Can't open %s: %s\n", path, strerror(errno));
        free(info);
		return NULL;
	}

	struct dirent *dt;
	while ((dt = readdir(d))) {
		if (dt->d_type != DT_LNK)
			continue;

		snprintf(buf, ARRAY_SIZE(buf), "%s/%s/uevent", path, dt->d_name);
		add_uevent_entry(info, buf);
	}

	if (closedir(d)) {
		LOGW("Can't close %s: %s\n", path, strerror(errno));
	}

	return info;
}

void free_block_devices(uevent_block_info_t *info)
{
	int i;

	for (i = 0; i < info->num_entries; i++) {
		uevent_block_t *event = &info->entries[i];
		if (event->devname)
			free(event->devname);
		if (event->partname)
			free(event->partname);
		free(event);
	}

	free(info);
}

uevent_block_t *get_blockinfo_for_path(uevent_block_info_t *info, const char *path)
{
	int i;
	char *search_name = NULL;
	bool use_name = false;
    const char* search_devname = NULL;
	uevent_block_t *ret = NULL;

    int mbpath_len = strlen(MBPATH_ROOT);
    if(!strncmp(path, MBPATH_ROOT, mbpath_len))
        path+=mbpath_len;

	if (strstr(path, "by-name") != NULL) {
		search_name = util_basename(path);
        if(!search_name) {
            return NULL;
        }
		use_name = true;
	} else {
        const char* prefix = "/dev/block/";
        if(strncmp(path, prefix, strlen(prefix))) {
            return NULL;
        }

        search_devname = path + strlen(prefix);
	}

	for (i = 0; i < info->num_entries; i++) {
		uevent_block_t *event = &info->entries[i];

		if (use_name && event->partname && !strcmp(event->partname, search_name)) {
			ret = event;
			break;
		}
        else if (!use_name && event->devname && !strcmp(event->devname, search_devname)) {
			ret = event;
			break;
		}
	}

	free(search_name);

	return ret;
}

char *uevent_realpath(uevent_block_info_t *info, const char *path, char *resolved_path)
{
    int rc;

	uevent_block_t *bi = get_blockinfo_for_path(info, path);
	if (!bi)
		return NULL;

	rc = snprintf(resolved_path, PATH_MAX, "/dev/block/%s", bi->devname);
    if(rc<=0)
        return NULL;

	return resolved_path;
}

int uevent_create_nodes(uevent_block_info_t *info, const char *path)
{
	int i;
	char buf[PATH_MAX];
	char path_block[PATH_MAX];
    int rc;

    // build block device path
	rc = snprintf(path_block, sizeof(path_block), "%s/block", path);
    if(rc<0) {
        return rc;
    }

    // create block directory
	rc = util_mkdir(path_block);
    if(rc<0) {
        return rc;
    }

    // create all block nodes
	for (i = 0; i < info->num_entries; i++) {
		uevent_block_t *bi = &info->entries[i];

        // build node path
		rc = snprintf(buf, sizeof(buf), "%s/%s", path_block, bi->devname);
        if(rc<0) {
            return rc;
        }

        // create node
		rc = mknod(buf, S_IFBLK | 0600, makedev(bi->major, bi->minor));
        if(rc<0) {
            return rc;
        }    
	}

	return 0;
}

int uevent_mount(uevent_block_t *bi, const char *target,
                  const char *filesystemtype, unsigned long mountflags,
                  const void *data)
{
    int rc;
    char buf[PATH_MAX];

    // build dev name
    rc = snprintf(buf, sizeof(buf), MBPATH_DEV"/block/%s", bi->devname);
    if(rc<0) {
        return rc;
    }

    // mount
    return util_mount(buf, target, filesystemtype, mountflags, data);
}
