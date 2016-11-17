#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include <common.h>
#include <util.h>
#include <lib/sefbinparser.h>

#define LOG_TAG "SEFBINPARSER"
#include <lib/log.h>

#define SELINUX_MAGIC_COMPILED_FCONTEXT 0xf97cff8a

static void safe_read(int fildes, void *buf, size_t nbyte)
{
    ssize_t bytes = read(fildes, buf, nbyte);
    if (bytes<0 || (size_t)bytes!=nbyte) {
        MBABORT("can't read: %s\n", strerror(errno));
    }
}

static void safe_write(int fildes, const void *buf, size_t nbyte)
{
    ssize_t bytes = write(fildes, buf, nbyte);
    if (bytes<0 || (size_t)bytes!=nbyte) {
        MBABORT("can't write: %s\n", strerror(errno));
    }
}

static char *read_str(int fd, int nullinlen)
{
    uint32_t len;

    safe_read(fd, &len, sizeof(len));
    if (!nullinlen) len++;
    char *s = safe_malloc(len);
    safe_read(fd, s, len);

    return s;
}

static void write_str(int fd, int nullinlen, const char *s)
{
    uint32_t len = strlen(s);
    uint32_t len_write = len;

    if (nullinlen)
        len_write++;

    safe_write(fd, &len_write, sizeof(len_write));
    safe_write(fd, s, len+1);
}

static int32_t sefbin_get_stemid(sefbin_file_t *seffile, const char *name)
{
    int32_t i = 0;

    sefbin_stem_t *sefstem;
    list_for_every_entry(&seffile->stems, sefstem, sefbin_stem_t, node) {
        if (!strcmp(sefstem->name, name))
            return i;

        i++;
    }

    return -1;
}

static const char *sefbin_get_stemname(sefbin_file_t *seffile, int32_t id)
{
    int32_t i = 0;

    sefbin_stem_t *sefstem;
    list_for_every_entry(&seffile->stems, sefstem, sefbin_stem_t, node) {
        if (id==i)
            return sefstem->name;

        i++;
    }

    return NULL;
}

static void *datadup(void *data, size_t sz)
{
    void *ndata = safe_malloc(sz);
    memcpy(ndata, data, sz);
    return ndata;
}

sefbin_file_t *sefbin_parse(const char *filename, int allow_magicerror)
{
    uint32_t magic;
    uint32_t num_stems;
    uint32_t nspec;
    uint32_t i;

    sefbin_file_t *seffile = safe_malloc(sizeof(sefbin_file_t));
    list_initialize(&seffile->stems);
    list_initialize(&seffile->specs);

    int fd = open(filename, O_RDONLY);
    if (fd<0) {
        MBABORT("Can't open file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }

    // magic
    safe_read(fd, &magic, sizeof(magic));
    if (magic!=SELINUX_MAGIC_COMPILED_FCONTEXT) {
        if (allow_magicerror)
            LOGE("invalid magic: 0x%08x\n", magic);
        else
            MBABORT("invalid magic: 0x%08x\n", magic);
        return NULL;
    }

    // version
    safe_read(fd, &seffile->version, sizeof(seffile->version));

    // pcre version
    safe_read(fd, &seffile->pcre_version_size, sizeof(seffile->pcre_version_size));
    seffile->pcre_version = safe_malloc(seffile->pcre_version_size);
    safe_read(fd, seffile->pcre_version, seffile->pcre_version_size);

    // stems
    safe_read(fd, &num_stems, sizeof(num_stems));
    for (i=0; i<num_stems; i++) {
        uint32_t len;

        sefbin_stem_t *sefstem = safe_malloc(sizeof(sefbin_stem_t));

        safe_read(fd, &len, sizeof(len));
        sefstem->name = safe_malloc(len+1);
        safe_read(fd, sefstem->name, len+1);

        list_add_tail(&seffile->stems, &sefstem->node);
    }

    // specs
    safe_read(fd, &nspec, sizeof(nspec));
    for (i=0; i<nspec; i++) {
        sefbin_spec_t *sefspec = safe_malloc(sizeof(sefbin_spec_t));

        sefspec->context = read_str(fd, 1);
        sefspec->regex = read_str(fd, 1);
        safe_read(fd, &sefspec->mode, sizeof(sefspec->mode));
        safe_read(fd, &sefspec->stem_id, sizeof(sefspec->stem_id));
        safe_read(fd, &sefspec->hasMetaChars, sizeof(sefspec->hasMetaChars));
        safe_read(fd, &sefspec->prefix_len, sizeof(sefspec->prefix_len));

        safe_read(fd, &sefspec->pcre_data_size, sizeof(sefspec->pcre_data_size));
        sefspec->pcre_data = safe_malloc(sefspec->pcre_data_size);
        safe_read(fd, sefspec->pcre_data, sefspec->pcre_data_size);

        safe_read(fd, &sefspec->pcre_studydata_size, sizeof(sefspec->pcre_studydata_size));
        sefspec->pcre_studydata = safe_malloc(sefspec->pcre_studydata_size);
        safe_read(fd, sefspec->pcre_studydata, sefspec->pcre_studydata_size);

        list_add_tail(&seffile->specs, &sefspec->node);
    }

    close(fd);

    return seffile;
}

int sefbin_write(sefbin_file_t *seffile, const char *filename)
{
    uint32_t magic = SELINUX_MAGIC_COMPILED_FCONTEXT;

    int fd = open(filename, O_WRONLY|O_TRUNC|O_CREAT, 0644);
    if (fd<0) {
        MBABORT("Can't open file '%s': %s\n", filename, strerror(errno));
        return -1;
    }

    // magic
    safe_write(fd, &magic, sizeof(magic));

    // version
    safe_write(fd, &seffile->version, sizeof(seffile->version));

    // pcre version
    safe_write(fd, &seffile->pcre_version_size, sizeof(seffile->pcre_version_size));
    safe_write(fd, seffile->pcre_version, seffile->pcre_version_size);

    // stems-count
    uint32_t num_stems = list_length(&seffile->stems);
    safe_write(fd, &num_stems, sizeof(num_stems));

    // stems
    sefbin_stem_t *sefstem;
    list_for_every_entry(&seffile->stems, sefstem, sefbin_stem_t, node) {
        write_str(fd, 0, sefstem->name);
    }

    // specs-count
    uint32_t num_specs = list_length(&seffile->specs);
    safe_write(fd, &num_specs, sizeof(num_specs));

    // specs
    sefbin_spec_t *sefspec;
    list_for_every_entry(&seffile->specs, sefspec, sefbin_spec_t, node) {
        write_str(fd, 1, sefspec->context);
        write_str(fd, 1, sefspec->regex);
        safe_write(fd, &sefspec->mode, sizeof(sefspec->mode));
        safe_write(fd, &sefspec->stem_id, sizeof(sefspec->stem_id));
        safe_write(fd, &sefspec->hasMetaChars, sizeof(sefspec->hasMetaChars));
        safe_write(fd, &sefspec->prefix_len, sizeof(sefspec->prefix_len));

        safe_write(fd, &sefspec->pcre_data_size, sizeof(sefspec->pcre_data_size));
        safe_write(fd, sefspec->pcre_data, sefspec->pcre_data_size);

        safe_write(fd, &sefspec->pcre_studydata_size, sizeof(sefspec->pcre_studydata_size));
        safe_write(fd, sefspec->pcre_studydata, sefspec->pcre_studydata_size);
    }

    close(fd);

    return 0;
}

int sefbin_append(sefbin_file_t *dst, sefbin_file_t *src)
{

    // stems
    sefbin_stem_t *sefstem;
    list_for_every_entry(&src->stems, sefstem, sefbin_stem_t, node) {
        if (sefbin_get_stemid(dst, sefstem->name)<0) {
            // add new stem
            sefbin_stem_t *nsefstem = safe_malloc(sizeof(sefbin_stem_t));
            nsefstem->name = safe_strdup(sefstem->name);
            list_add_tail(&dst->stems, &nsefstem->node);
        }
    }

    // specs
    sefbin_spec_t *sefspec;
    list_for_every_entry(&src->specs, sefspec, sefbin_spec_t, node) {
        sefbin_spec_t *nsefspec = safe_malloc(sizeof(sefbin_spec_t));

        int32_t stem_id = sefspec->stem_id;
        if (stem_id>=0) {
            const char *stem_name = sefbin_get_stemname(src, sefspec->stem_id);
            stem_id = sefbin_get_stemid(dst, stem_name);
        }

        nsefspec->context = safe_strdup(sefspec->context);
        nsefspec->regex = safe_strdup(sefspec->regex);
        nsefspec->mode = sefspec->mode;
        nsefspec->stem_id = stem_id;
        nsefspec->hasMetaChars = sefspec->hasMetaChars;
        nsefspec->prefix_len = sefspec->prefix_len;

        nsefspec->pcre_data_size = sefspec->pcre_data_size;
        nsefspec->pcre_data = datadup(sefspec->pcre_data, sefspec->pcre_data_size);

        nsefspec->pcre_studydata_size = sefspec->pcre_studydata_size;
        nsefspec->pcre_studydata = datadup(sefspec->pcre_studydata, sefspec->pcre_studydata_size);

        list_add_tail(&dst->specs, &nsefspec->node);
    }

    return 0;
}

static char *add_prefix(const char *prefix, const char *s)
{
    size_t len = strlen(prefix) + strlen(s) + 1;

    char *s2 = safe_malloc(len);
    SAFE_SNPRINTF_RET(LOGE, NULL, s2, len, "%s%s", prefix, s);

    return s2;
}

static void compile_regex(sefbin_file_t *specfile, sefbin_spec_t *spec)
{
    const char *tmperrbuf;
    char *reg_buf, *anchored_regex, *cp;
    size_t len;
    int erroff;

    /* Skip the fixed stem. */
    reg_buf = spec->regex;
    if (spec->stem_id >= 0) {
        const char *stem_name = sefbin_get_stemname(specfile, spec->stem_id);

        reg_buf += strlen(stem_name);
    }

    /* Anchor the regular expression. */
    len = strlen(reg_buf);
    cp = anchored_regex = safe_malloc(len + 3);

    /* Create ^...$ regexp.  */
    *cp++ = '^';
    memcpy(cp, reg_buf, len);
    cp += len;
    *cp++ = '$';
    *cp = '\0';

    /* Compile the regular expression. */
    spec->pcre_data = pcre_compile(anchored_regex, PCRE_DOTALL, &tmperrbuf,
                                   &erroff, NULL);
    free(anchored_regex);
    if (!spec->pcre_data) {
        MBABORT("regex error: %s\n", tmperrbuf);
    }

    spec->pcre_extra = pcre_study(spec->pcre_data, 0, &tmperrbuf);
    if (!spec->pcre_studydata && tmperrbuf) {
        MBABORT("regex error: %s\n", tmperrbuf);
    }
}

int sefbin_append_multiboot_rules(sefbin_file_t *dst)
{
    int rc;
    size_t size;

    // get /dev stem id
    int32_t dev_stem_id = sefbin_get_stemid(dst, "/dev");
    if (dev_stem_id<0) {
        return 0;
    }

    // get /multiboot stem id
    int32_t multiboot_stem_id = sefbin_get_stemid(dst, "/multiboot");
    if (multiboot_stem_id<0) {
        // add new stem for /multiboot
        sefbin_stem_t *nsefstem = safe_malloc(sizeof(sefbin_stem_t));
        nsefstem->name = safe_strdup("/multiboot");
        list_add_tail(&dst->stems, &nsefstem->node);

        multiboot_stem_id = sefbin_get_stemid(dst, "/multiboot");
        if (multiboot_stem_id<0) {
            MBABORT("can't find multiboot stem\n");
        }
    }

    // specs
    sefbin_spec_t *sefspec;
    sefbin_spec_t *tmpentry;
    list_for_every_entry_safe(&dst->specs, sefspec, tmpentry, sefbin_spec_t, node) {
        if (!util_startswith(sefspec->regex, "/dev"))
            continue;

        sefbin_spec_t *nsefspec = safe_malloc(sizeof(sefbin_spec_t));

        // check is the id is correct
        int32_t stem_id = sefspec->stem_id;
        if (stem_id>=0) {
            if (stem_id != dev_stem_id) {
                MBABORT("%s has invalid stem id %d\n", sefspec->context, stem_id);
            }
        }
        stem_id = multiboot_stem_id;

        nsefspec->context = safe_strdup(sefspec->context);
        nsefspec->regex = add_prefix("/multiboot", sefspec->regex);
        nsefspec->mode = sefspec->mode;
        nsefspec->stem_id = stem_id;
        nsefspec->hasMetaChars = sefspec->hasMetaChars;
        nsefspec->prefix_len = sefspec->prefix_len + 10;

        // compile regex
        compile_regex(dst, nsefspec);

        // get pcre data size
        rc = pcre_fullinfo(nsefspec->pcre_data, NULL, PCRE_INFO_SIZE, &size);
        if (rc < 0) {
            MBABORT("PCRE_INFO_SIZE error: %d\n", rc);
        }
        nsefspec->pcre_data_size = size;

        // get pcre study data size
        rc = pcre_fullinfo(nsefspec->pcre_data, nsefspec->pcre_extra, PCRE_INFO_STUDYSIZE, &size);
        if (rc < 0) {
            MBABORT("PCRE_INFO_STUDYSIZE error: %d\n", rc);
        }
        nsefspec->pcre_studydata = nsefspec->pcre_extra->study_data;
        nsefspec->pcre_studydata_size = size;

        list_add_tail(&dst->specs, &nsefspec->node);
    }

    return 0;
}
