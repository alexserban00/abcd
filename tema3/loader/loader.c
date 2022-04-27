/*
 * Loader Implementation
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>
#include <sys/mman.h>

#include "exec_parser.h"

#define MMAP_FLAG MAP_FIXED | MAP_PRIVATE

static so_exec_t *exec;
static struct sigaction memsig;

int fd;
int sizePage;

void execute_signal(int signum, siginfo_t *info, void *context)
{
	char foundSegment = 0x0;
	int page_segment_index = -1;
	int page_index, msync_ret;

	for (int i = 0; i < exec->segments_no; i++) {
		if ((int) info->si_addr >= exec->segments[i].vaddr && (int) info->si_addr <= exec->segments[i].vaddr + exec->segments[i].mem_size) {
			foundSegment = 0x1;
			page_segment_index = i;
			break;
		}
	}

	if (!foundSegment) {
		memsig.sa_sigaction(signum, info, context);
		return;
	}

	else {
		uintptr_t vaddr = exec->segments[page_segment_index].vaddr;
		unsigned int file_size = exec->segments[page_segment_index].file_size;
		unsigned int mem_size = exec->segments[page_segment_index].mem_size;
		unsigned int offset = exec->segments[page_segment_index].offset;
		unsigned int perm = exec->segments[page_segment_index].perm;
		uintptr_t addr = (uintptr_t) info->si_addr;
		uintptr_t page_addr;

		page_index = floor((addr - vaddr) / sizePage);
		page_addr = vaddr + (page_index * sizePage);
		msync_ret = msync((int *) page_addr, sizePage, 0);

		if (msync_ret == 0) {
			memsig.sa_sigaction(signum, info, context);
			return;
		}

		if (msync_ret == -1 && errno == ENOMEM) {
			if (mmap((void *) page_addr, sizePage, perm, MMAP_FLAG, fd, offset + page_index * sizePage) == MAP_FAILED) {
				memsig.sa_sigaction(signum, info, context);
				return;
			}

			if (page_addr <= vaddr + file_size
				&& page_addr + sizePage > vaddr + file_size
				&& page_addr + sizePage <= vaddr + mem_size) {
				unsigned int end = (unsigned int) sizePage - (vaddr + file_size - page_addr);

				memset((void *) vaddr + file_size, 0, end);
				return;
			}

			else if (page_addr > vaddr + file_size && page_addr + sizePage < vaddr + mem_size) {

				memset((void *) page_addr, 0, sizePage);
				return;
			}

			else if (page_addr > vaddr + file_size && page_addr < vaddr + mem_size && page_addr + sizePage >= vaddr + mem_size) {
				unsigned int count = (unsigned int) ((vaddr + mem_size) - page_addr);

				memset((void *) page_addr, 0, count);
				return;
			}

			else if (page_addr <= vaddr + file_size && page_addr + sizePage >= vaddr + mem_size) {

				unsigned int count = (unsigned int) (mem_size - file_size);

				memset((void *) vaddr + file_size, 0, count);
				return;
			}
		}
	}
}


int so_init_loader(void)
{
	struct sigaction sig;

	sizePage = getpagesize();

	sig.sa_sigaction = execute_signal;
	sig.sa_flags = SA_SIGINFO;

	if (sigemptyset(&sig.sa_mask) == -1) {
		perror("Eroare sigemptyset");
		exit(1);
	}

	if (sigaddset(&sig.sa_mask, SIGSEGV) == -1) {
		perror("Eroare sigaddset");
		exit(1);
	}

	if (sigaction(SIGSEGV, &sig, &memsig) == -1) {
		perror("Eroare sigaction");
		exit(1);
	}

	return -1;
}


int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		perror("Eroare deschidere executabil");
		return -1;
	}

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);

	return -1;
}
