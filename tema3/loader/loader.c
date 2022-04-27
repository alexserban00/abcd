#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction old_action;
int fd;
int page_size;

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	int i, page_found = 0, page_segment_index = -1;
	void *mmap_ret;
	int page_index, msync_ret;

	for (i = 0; i < exec->segments_no; i++) {
		if ((int) info->si_addr >= exec->segments[i].vaddr
				&& (int) info->si_addr <= exec->segments[i].vaddr
				+ exec->segments[i].mem_size) {
			page_found = 1;
			page_segment_index = i;
			break;
		}

	}
	if (page_found == 0) {
		old_action.sa_sigaction(signum, info, context);
		return;
	}

	uintptr_t vaddr = exec->segments[page_segment_index].vaddr;
	unsigned int file_size = exec->segments[page_segment_index].file_size;
	unsigned int mem_size = exec->segments[page_segment_index].mem_size;
	unsigned int offset = exec->segments[page_segment_index].offset;
	unsigned int perm = exec->segments[page_segment_index].perm;
	uintptr_t addr = (uintptr_t) info->si_addr;
	uintptr_t page_addr;

	if (page_found == 1) {
		page_index = floor((addr - vaddr) / page_size);
		page_addr = vaddr + (page_index * page_size);
		msync_ret = msync((int *) page_addr, page_size, 0);
		if (msync_ret == 0) {
			old_action.sa_sigaction(signum, info, context);
			return;
		}
		if (msync_ret == -1 && errno == ENOMEM) {
			mmap_ret = mmap((void *) page_addr, page_size, perm,
					MAP_FIXED | MAP_PRIVATE, fd,
					offset + page_index * page_size);
			if (mmap_ret == MAP_FAILED) {
				old_action.sa_sigaction(signum, info, context);
				return;
			}
			if (page_addr <= vaddr + file_size
				&& page_addr + page_size > vaddr + file_size
				&& page_addr + page_size <= vaddr + mem_size) {
				unsigned int end = (unsigned int) page_size - (vaddr + file_size - page_addr);

				memset((void *) vaddr + file_size, 0, end);
				return;
			} else if (page_addr > vaddr + file_size
				&& page_addr + page_size < vaddr + mem_size) {

				memset((void *) page_addr, 0, page_size);
				return;
			} else if (page_addr > vaddr + file_size
				&& page_addr < vaddr + mem_size
				&& page_addr + page_size >= vaddr + mem_size) {
				unsigned int count = (unsigned int) ((vaddr + mem_size) - page_addr);

				memset((void *) page_addr, 0, count);
				return;
			} else if (page_addr <= vaddr + file_size
				&& page_addr + page_size >= vaddr + mem_size) {

				unsigned int count = (unsigned int) (mem_size - file_size);

				memset((void *) vaddr + file_size, 0, count);
				return;
			}
		}
	}
}

int so_init_loader(void)
{
	//set signal
	struct sigaction action;
	int rc;

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &old_action);
	if (rc < 0)
		return -1;

	return -1;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY, 0644);
	if (fd < 0)
		return -1;
	page_size = getpagesize();

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
