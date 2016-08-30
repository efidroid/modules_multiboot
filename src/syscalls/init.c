#define _GNU_SOURCE
#include <fcntl.h>

#define LOG_TAG "SYSCALLS"
#include <lib/log.h>

#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <syshook.h>
#include <sys/syscall.h>
#include <common.h>

#include "syscalls_private.h"

#define register_syscall(name) sys_call_table[SYS_##name] = sys_##name;

static void *sys_call_table[SYSHOOK_NUM_SYSCALLS] = {0};
multiboot_data_t *syshook_multiboot_data = NULL;

static int multiboot_trace_create_process(UNUSED syshook_process_t *process)
{
    if (!process) {
        MBABORT("process is NULL\n");
    }
    if (process->pdata) {
        MBABORT("pdata does already exist\n");
    }

    syshook_pdata_t *pdata = safe_calloc(1, sizeof(syshook_pdata_t));
    if (!pdata) {
        MBABORT("no pdata\n");
    }

    syshook_process_t *pprocess = get_process_by_tid(process->context, process->ppid);
    if (pprocess) {
        syshook_pdata_t *ppdata = pprocess->pdata;
        if (!ppdata) {
            MBABORT("no pdata\n");
        }
        if (!ppdata->fdtable) {
            MBABORT("no fdtable\n");
        }

        // use the same fdtable
        if ((process->clone_flags & (CLONE_FILES|CLONE_VFORK|CLONE_VM))) {
            pthread_mutex_lock(&ppdata->fdtable->lock);
            pdata->fdtable = ppdata->fdtable;
            pdata->fdtable->refs++;
            pthread_mutex_unlock(&ppdata->fdtable->lock);
        }

        else {
            // duplicate fd table
            pdata->fdtable = fdtable_dup(ppdata->fdtable);
            if (!pdata->fdtable) return -1;
        }
    }

    else {
        // allocate new fdtable
        pdata->fdtable = fdtable_create();
        if (!pdata->fdtable) return -1;
    }

    process->pdata = pdata;

    return 0;
}

static int multiboot_trace_destroy_process(UNUSED syshook_process_t *process)
{
    syshook_pdata_t *pdata = process->pdata;
    if (!pdata) {
        MBABORT("no pdata\n");
    }

    pthread_mutex_lock(&pdata->fdtable->lock);
    pdata->fdtable->refs--;
    if (pdata->fdtable->refs==0) {
        // free fd table
        fdtable_free(pdata->fdtable);
    } else {
        pthread_mutex_unlock(&pdata->fdtable->lock);
    }

    free(pdata);

    return 0;
}

static int multiboot_trace_execve_process(UNUSED syshook_process_t *process)
{
    syshook_pdata_t *pdata = process->pdata;
    if (!pdata) {
        return -1;
    }

    // remove all fd's with O_CLOEXEC
    fdinfo_t *tmpentry;
    fdinfo_t *entry;
    pthread_mutex_lock(&pdata->fdtable->lock);
    list_for_every_entry_safe(&pdata->fdtable->files, entry, tmpentry, fdinfo_t, node) {
        if (entry->flags & O_CLOEXEC) {
            fdinfo_free(entry, 1);
        }
    }
    pthread_mutex_unlock(&pdata->fdtable->lock);

    return 0;
}

int multiboot_exec_tracee(char **par)
{
    syshook_multiboot_data = multiboot_get_data();

    register_syscall(openat);
    register_syscall(open);
    register_syscall(close);
    register_syscall(dup3);
    register_syscall(dup2);
    register_syscall(dup);
    register_syscall(mount);
    register_syscall(fcntl);
    register_syscall(fcntl64);
    register_syscall(execve);

    syshook_context_t *context = syshook_create_context(sys_call_table);
    context->create_process = multiboot_trace_create_process;
    context->destroy_process = multiboot_trace_destroy_process;
    context->execve_process = multiboot_trace_execve_process;

    return syshook_execvp_ex(context, par);
}
