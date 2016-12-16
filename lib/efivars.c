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
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>

#include <lib/cksum.h>
#include <lib/efivars.h>
#include <common.h>
#include <util.h>

#define LOG_TAG "EFIVARS"
#include <lib/log.h>


#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#define ALIGN(a, b) ROUNDUP(a, b)
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define EFIVAR_MAGIC 0x6f69766e // nvio

#define EFIVAR_ENTRY_SIZE(name, datasize) \
        (sizeof(uint32_t) + /* namesize */ \
        ALIGN((strlen(name)+1)*sizeof(uint16_t), sizeof(uint32_t)) + /* name */ \
        ALIGN(sizeof(efi_guid_t), sizeof(uint32_t)) + /* guid */ \
        ALIGN(sizeof(uint32_t), sizeof(uint32_t)) + /* attributes */ \
        sizeof(uint32_t) + /* datasize */ \
        ALIGN(datasize, sizeof(uint32_t))) /* data */

#define EFIVARDEV MBPATH_DEV "/efivardev"

typedef struct {
    uint32_t magic;
    uint32_t data_size;
    uint32_t crc32;
} __attribute__((packed)) efivar_hdr_t;

typedef struct {
    // device for writing
    void *buf;
    uint32_t bufsize;
    bool found;

    // backup data in case the variable exists
    uint16_t *name;
    uint32_t namesize;
    const void *data;
    uint32_t datasize;
    efi_guid_t guid;
    uint32_t attributes;
} efivar_pdata_t;

typedef unsigned long addr_t;
typedef int (*efivar_callback_t)(void *pdata, const uint16_t *name, const uint32_t namesize, const void *data,
                                 const uint32_t datasize, efi_guid_t guid, uint32_t attributes);

static int copy_ansi2unicodestr(uint16_t **outdst, const char *src, size_t *outsz)
{
    uint16_t *dst = NULL;
    size_t sz = (strlen(src)+1)*sizeof(uint16_t);

    *outdst = dst = malloc(sz);
    if (!dst) return (int)dst;

    while (*src) {
        *(dst++) = *(src++);
    }
    *dst = 0;

    if (outsz)
        *outsz = sz;

    return 0;
}

static char *efivar_getdev(void)
{
    // check if blockinfo is available
    multiboot_data_t *mbdata = multiboot_get_data();
    if (!mbdata || !mbdata->blockinfo || !mbdata->mbfstab) goto err;

    // get fstab rec for nvvars partition
    struct fstab_rec *rec = fs_mgr_nvvars(mbdata->mbfstab);
    if (!rec) goto err;

    // get block of our partition
    uevent_block_t *bi = get_blockinfo_for_path(mbdata->blockinfo, rec->blk_device);
    if (!bi) goto err;

    // try EFIVARDEV
    if (util_exists(EFIVARDEV, true)) {
        return strdup(EFIVARDEV);
    }

    // try to create /efivardev
    if (!mknod(EFIVARDEV, S_IRUSR | S_IWUSR | S_IFBLK, makedev(bi->major, bi->minor))) {
        return strdup(EFIVARDEV);
    }

err:
    // give up
    LOGE("Can't find efivars partition\n");

    return NULL;
}

static int efivar_read_to_buf(const char *device, void **buf, uint32_t *outdatasize)
{
    off_t off;
    int fd;
    ssize_t nbytes;
    int rc = 0;
    efivar_hdr_t hdr;
    uint8_t *data = NULL;

    if (!device) {
        LOGE("nvvars device is NULL\n");
        return -1;
    }

    // open device
    fd = open(device, O_RDONLY);
    if (fd<0) {
        LOGE("can't open %s: %s\n", device, strerror(-fd));
        return fd;
    }

    // seek to start of the NVVARS data
    off = lseek(fd, -0x10000, SEEK_END);
    if (off<0) {
        perror("seek failed");
        rc = (int)fd;
        goto err_close;
    }

    // read header
    nbytes = read(fd, &hdr, sizeof(hdr));
    if (nbytes!=sizeof(hdr)) {
        perror("reading header failed");
        rc = (int)nbytes;
        goto err_close;
    }

    // check magic
    if (hdr.magic!=EFIVAR_MAGIC) {
        LOGE("Invalid magic\n");
        rc = EINVAL;
        goto err_close;
    }

    if (outdatasize)
        *outdatasize = hdr.data_size;

    if (buf) {
        // allocate memory for data
        data = malloc(hdr.data_size);
        if (!data) {
            LOGE("allocating data failed\n");
            goto err_close;
        }

        // read whole data area into memory
        nbytes = read(fd, data, hdr.data_size);
        if (nbytes!=(ssize_t)hdr.data_size) {
            perror("reading data failed");
            rc = (int)nbytes;
            goto err_free;
        }

        // verify CRC32
        uint32_t crc32sum = cksum_crc32(0, data, hdr.data_size);
        if (hdr.crc32!=crc32sum) {
            LOGE("Invalid checksum\n");
            rc = -EIO;
            goto err_free;
        }

        *buf = data;
    }

    goto err_close;

err_free:
    free(data);

err_close:
    close(fd);

    return rc;
}

static int efivar_write_from_buf(const char *device, void *data, uint32_t datasize)
{
    off_t off;
    int fd;
    size_t nbytes;
    int rc = 0;

    if (!device) {
        LOGE("nvvars device is NULL\n");
        return -1;
    }

    // open device
    fd = open(device, O_WRONLY);
    if (fd<0) {
        LOGE("can't open %s\n", device);
        return fd;
    }

    // seek to start of the NVVARS data
    off = lseek(fd, -0x10000, SEEK_END);
    if (off<0) {
        perror("seek failed");
        rc = (int)fd;
        goto err_close;
    }

    // write data
    nbytes = write(fd, data, datasize);
    if (nbytes!=datasize) {
        perror("write failed");
        rc = (int)nbytes;
        goto err_close;
    }

err_close:
    close(fd);

    return rc;
}

static int efivar_iterate(const void *buf, uint32_t bufsize, efivar_callback_t cb, void *pdata)
{
    int rc = 0;

    uint32_t namesize;
    const uint8_t *dataptr = buf;
    do {
        const uint16_t *name;
        efi_guid_t guid;
        uint32_t attributes;
        uint32_t datasize;
        const uint8_t *data;

        // get namesize
        memcpy(&namesize, dataptr, sizeof(namesize));
        dataptr+=sizeof(uint32_t);
        // get name
        name = (uint16_t *)dataptr;
        dataptr+=ALIGN(namesize, sizeof(uint32_t));

        // get guid
        memcpy(&guid, dataptr, sizeof(guid));
        dataptr+=ALIGN(sizeof(guid), sizeof(uint32_t));

        // get attributes
        memcpy(&attributes, dataptr, sizeof(attributes));
        dataptr+=sizeof(uint32_t);

        // get datasize
        memcpy(&datasize, dataptr, sizeof(datasize));
        dataptr+=sizeof(uint32_t);

        // get data
        data = dataptr;
        dataptr+=ALIGN(datasize, sizeof(uint32_t));

        rc=cb(pdata, name, namesize, data, datasize, guid, attributes);
        if (rc) break;

    } while (namesize>0 && (uint32_t)(dataptr-(uint8_t *)buf)<bufsize);

    return rc;
}

static int efivar_append(void **buf, const uint16_t *name, const uint32_t namesize, const void *data,
                         const uint32_t datasize, efi_guid_t guid, uint32_t attributes)
{
    uint8_t *bufptr = *buf;

    // copy namesize
    memcpy(bufptr, &namesize, sizeof(namesize));
    bufptr += ALIGN(sizeof(namesize), sizeof(uint32_t));

    // copy name
    memcpy(bufptr, name, namesize);
    bufptr += ALIGN(namesize, sizeof(uint32_t));

    // copy GUID
    memcpy(bufptr, &guid, sizeof(guid));
    bufptr += ALIGN(sizeof(guid), sizeof(uint32_t));

    // copy attributes
    memcpy(bufptr, &attributes, sizeof(attributes));
    bufptr += ALIGN(sizeof(attributes), sizeof(uint32_t));

    // copy datasize
    memcpy(bufptr, &datasize, sizeof(datasize));
    bufptr += ALIGN(sizeof(datasize), sizeof(uint32_t));

    // copy data
    memcpy(bufptr, data, datasize);
    bufptr += ALIGN(datasize, sizeof(uint32_t));

    *buf = bufptr;

    return 0;
}

static int efivar_setvar_cb(void *_pdata, const uint16_t *name, const uint32_t namesize, const void *data,
                            const uint32_t datasize, efi_guid_t guid, uint32_t attributes)
{
    efivar_pdata_t *pdata = _pdata;

    if (pdata->namesize==namesize && !memcmp(pdata->name, name, namesize) &&
            !memcmp(&pdata->guid, &guid, sizeof(guid))) {
        free(pdata->name);
        pdata->name = (uint16_t *)name;
        pdata->namesize = namesize;
        pdata->data = data;
        pdata->datasize = datasize;
        pdata->guid = guid;
        pdata->attributes = attributes;

        pdata->found = true;

        return 0;
    }

    if (pdata->buf)
        return efivar_append(&pdata->buf, name, namesize, data, datasize, guid, attributes);

    return 0;
}

int efivar_get(const char *name, efi_guid_t *guid,
               uint32_t *attributes, uint32_t *datasize, void *data)
{
    void *rawdata = NULL;
    uint32_t rawdatasize = 0;
    int rc = 0;
    efivar_pdata_t pdata;

    memset(&pdata, 0, sizeof(pdata));

    // read variable data into buffer
    rc = efivar_read_to_buf(efivar_getdev(), &rawdata, &rawdatasize);
    if (rc || !rawdata) {
        LOGE("Error reading variable into buffer\n");
        return rc;
    }

    // find variable
    copy_ansi2unicodestr(&pdata.name, name, &pdata.namesize);
    pdata.guid = *guid;
    efivar_iterate(rawdata, rawdatasize, efivar_setvar_cb, &pdata);

    if (pdata.found) {
        // return variables

        if (data && *datasize>=pdata.datasize)
            memcpy(data, pdata.data, pdata.datasize);
        else rc = -ENOMEM;

        if (attributes)
            *attributes = pdata.attributes;

        *datasize = pdata.datasize;
    } else {
        free(pdata.name);
        rc = -ENOENT;
    }

    return rc;
}

int efivar_set(const char *name, efi_guid_t *guid,
               uint32_t attributes, uint32_t datasize, const void *data)
{
    void *rawdata = NULL;
    uint32_t rawdatasize = 0;
    int rc = 0;
    efivar_pdata_t pdata;

    memset(&pdata, 0, sizeof(pdata));

    // read variable data into buffer
    rc = efivar_read_to_buf(efivar_getdev(), &rawdata, &rawdatasize);
    if (rc || !rawdata) {
        LOGE("Error reading variable into buffer\n");
        return rc;
    }

    // allocate new buffer
    void *newdata = calloc(
                        sizeof(efivar_hdr_t) +
                        rawdatasize +
                        EFIVAR_ENTRY_SIZE(name, datasize),
                        1
                    );
    if (!newdata) {
        LOGE("Error allocating new buffer\n");
        return rc;
    }

    // copy all unchanged variables to the new buffer
    pdata.buf = newdata + 3*sizeof(uint32_t);
    copy_ansi2unicodestr(&pdata.name, name, &pdata.namesize);
    pdata.guid = *guid;
    efivar_iterate(rawdata, rawdatasize, efivar_setvar_cb, &pdata);

    if (attributes && datasize) {
        // append the new/changed variable
        copy_ansi2unicodestr(&pdata.name, name, &pdata.namesize);
        pdata.data = data;
        pdata.datasize = datasize;
        pdata.guid = *guid;
        pdata.attributes = attributes;
        efivar_append(&pdata.buf, pdata.name, pdata.namesize, pdata.data, pdata.datasize, pdata.guid, pdata.attributes);
    }

    uint32_t newdatasize = pdata.buf - (newdata + 3*sizeof(uint32_t));
    uint32_t *newdata32 = newdata;
    newdata32[0] = EFIVAR_MAGIC;
    newdata32[1] = newdatasize;
    newdata32[2] = cksum_crc32(0, newdata + 3*sizeof(uint32_t), newdatasize);

    rc = efivar_write_from_buf(efivar_getdev(), newdata, sizeof(efivar_hdr_t)+newdatasize);

    free(newdata);

    return rc;
}

int efivar_get_global(const char *name, uint32_t *datasize, void *data)
{
    efi_guid_t guid = EFI_GLOBAL_VARIABLE;
    return efivar_get(name, &guid, NULL, datasize, data);
}

int efivar_set_global(const char *name, uint32_t datasize, const void *data)
{
    efi_guid_t guid = EFI_GLOBAL_VARIABLE;
    return efivar_set(name, &guid, EFI_VARIABLE_DEFAULT_ATTRIBUTES, datasize, data);
}

int efivar_get_efidroid(const char *name, uint32_t *datasize, void *data)
{
    efi_guid_t guid = EFI_EFIDROID_VARIABLE;
    return efivar_get(name, &guid, NULL, datasize, data);
}

int efivar_set_efidroid(const char *name, uint32_t datasize, const void *data)
{
    efi_guid_t guid = EFI_EFIDROID_VARIABLE;
    return efivar_set(name, &guid, EFI_VARIABLE_DEFAULT_ATTRIBUTES, datasize, data);
}

int efivars_report_error(const char *error)
{
    return efivar_set_efidroid("EFIDroidErrorStr", strlen(error)+1, error);
}

int efivars_set_error(const char *fmt, ...)
{
    int n;
    int size = 100;
    char *p, *np;
    va_list ap;

    // alloc initial memory
    if ((p = malloc(size)) == NULL)
        return -1;

    while (1) {
        // Try to print in the allocated space
        va_start(ap, fmt);
        n = vsnprintf(p, size, fmt, ap);
        va_end(ap);

        // Check error code
        if (n < 0)
            return -1;

        // If that worked, we're done
        if (n < size)
            break;

        // Else try again with more space
        size = n + 1;
        if ((np = realloc (p, size)) == NULL) {
            free(p);
            return -1;
        } else {
            p = np;
        }
    }

    // write error to efi variable
    efivars_report_error(p);

    // cleanup
    free(p);

    return 0;
}
