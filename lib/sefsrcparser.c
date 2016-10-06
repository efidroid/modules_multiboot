#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include <common.h>
#include <util.h>
#include <lib/sefsrcparser.h>
#include <lib/list.h>

#define LOG_TAG "SEFSRCPARSER"
#include <lib/log.h>

typedef struct {
    list_node_t node;

    char *line;
    size_t line_len;
} sefsrc_item_t;

static int sefsrc_read_dev_rules(list_node_t *list, const char *filename)
{
    char *line_buf = NULL;
    size_t line_len = 0;
    FILE *context_file;
    ssize_t rc;

    // open file
    context_file = fopen(filename, "r");
    if (!context_file) {
        MBABORT("Error opening %s: %s\n", filename, strerror(errno));
    }

    // read dev lines
    while ((rc=getline(&line_buf, &line_len, context_file)) > 0) {
        if (!util_startswith(line_buf, "/dev"))
            continue;

        sefsrc_item_t *item = safe_malloc(sizeof(sefsrc_item_t));
        item->line = safe_strdup(line_buf);
        item->line_len = (size_t)rc;

        list_add_tail(list, &item->node);
    }

    // free buffer
    free(line_buf);

    // close file
    fclose(context_file);

    return 0;
}

int sefsrc_append_multiboot_rules(const char *filename)
{
    list_node_t list;

    // read dev rules
    list_initialize(&list);
    sefsrc_read_dev_rules(&list, filename);

    // open file
    int fd = open(filename, O_WRONLY|O_APPEND);
    if (fd<0) {
        MBABORT("Can't open file '%s': %s\n", filename, strerror(errno));
    }

    write(fd, "\n", 1);

    sefsrc_item_t *item;
    list_for_every_entry(&list, item, sefsrc_item_t, node) {
        write(fd, "/multiboot", 10);
        write(fd, item->line, item->line_len);
    }

    // close file
    close(fd);

    return 0;
}
