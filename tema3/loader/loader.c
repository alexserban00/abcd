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

#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction memsig;

int fd;
int sizePage;

void execute_signal(int signalnum, siginfo_t *info, void *context) {

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
