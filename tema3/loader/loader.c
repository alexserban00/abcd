#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cygwin/signal.h>

#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction old_action;
static int pageSize;
static int fd;

static void segv_handler(int signum, siginfo_t *info, void *context)
{
    int i;
    char *fault_addr, *base_addr, *page_addr, buffer[pageSize + 1];

    if (signum != SIGSEGV) {
        old_action.sa_sigaction(signum, info, context);
        return;
    }

    fault_addr = (char *)info->si_addr;
    base_addr = (char*)exec->base_addr;
    unsigned long page_number = (fault_addr - base_addr) / pageSize;
    page_addr = base_addr + page_number * pageSize;

    struct so_seg currentSegment;
    for (i=0; i<exec->segments_no; i++) {
        currentSegment = exec->segments[i];
        if ((char*)currentSegment.vaddr <= page_addr &&
            page_addr <= (char*)currentSegment.vaddr + currentSegment.mem_size) {

            mmap(page_addr, (size_t)pageSize, currentSegment.perm, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, fd, 0);

            lseek(fd, currentSegment.offset, SEEK_SET);
            read(fd, buffer, (size_t)pageSize);
            memcpy(page_addr, buffer, (size_t)pageSize);
            return;
        }
    }

    old_action.sa_sigaction(signum, info, context);
}

int so_init_loader(int fdd)
{
    fd = fdd;
    pageSize = getpagesize();

    struct sigaction action;
    action.sa_sigaction = segv_handler;
    sigemptyset(&action.sa_mask);
    sigaddset(&action.sa_mask, SIGSEGV);
    action.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &action, &old_action);

    return -1;
}

int so_execute(char *path, char *argv[])
{
    exec = so_parse_exec(path);
    if (!exec)
        return -1;

    so_start_exec(exec, argv);

    return -1;
}