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

void execute_segment(siginfo_t *sig_info, char *foundSegment, unsigned int *indexSegment)
{
	for (unsigned int i = 0; i < exec->segments_no; i++) {
		if ((int) sig_info->si_addr <= exec->segments[i].vaddr + exec->segments[i].mem_size) {
			*foundSegment = 0x1;
			*indexSegment = i;
			return;
		}
	}
}

void execute_signal(int signo, siginfo_t *sig_info, void *sig_context)
{
	char foundSegment = 0x0;
	unsigned int indexSegment;

	execute_segment(sig_info, &foundSegment, &indexSegment);

	if (!foundSegment) {
		memsig.sa_sigaction(signo, sig_info, sig_context);
		return;
	}

	else {
		uintptr_t vaddr = exec->segments[indexSegment].vaddr;
		unsigned int file_size = exec->segments[indexSegment].file_size;
		unsigned int mem_size = exec->segments[indexSegment].mem_size;
		unsigned int offset = exec->segments[indexSegment].offset;
		unsigned int perm = exec->segments[indexSegment].perm;
		uintptr_t addr = (uintptr_t) sig_info->si_addr;
		uintptr_t page_addr;

		int page_index;
		int msync_ret;

		page_index = floor((addr - vaddr) / sizePage);
		page_addr = vaddr + (page_index * sizePage);
		msync_ret = msync((int *) page_addr, sizePage, 0);

		if (!msync_ret) {
			memsig.sa_sigaction(signo, sig_info, sig_context);
			return;
		}

		else if (msync_ret == -1 && errno == ENOMEM) {
			if (mmap((void *) page_addr, sizePage, perm, MMAP_FLAG, fd, offset + page_index * sizePage) == MAP_FAILED) {
				memsig.sa_sigaction(signo, sig_info, sig_context);
				return;
			}

			if (page_addr <= vaddr + file_size && page_addr + sizePage > vaddr + file_size && page_addr + sizePage <= vaddr + mem_size)
				memset((void *) vaddr + file_size, 0, sizePage - (vaddr + file_size - page_addr));

			else if (page_addr > vaddr + file_size && page_addr + sizePage < vaddr + mem_size)
				memset((void *) page_addr, 0, sizePage);

			else if (page_addr > vaddr + file_size && page_addr < vaddr + mem_size && page_addr + sizePage >= vaddr + mem_size)
				memset((void *) page_addr, 0, vaddr + mem_size - page_addr);

			else if (page_addr >= vaddr + mem_size - sizePage && page_addr <= vaddr + file_size)
				memset((void *) vaddr + file_size, 0, mem_size - file_size);
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
