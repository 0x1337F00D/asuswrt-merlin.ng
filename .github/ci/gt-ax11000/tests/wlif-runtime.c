/* Appended to the actual runner extracted from wlif-shell-hardening.patch. */
#include <assert.h>
#include <sys/stat.h>
#include <sys/prctl.h>

static void check_reaped(void)
{
	int status;
	errno = 0;
	assert(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
}

int main(int argc, char **argv)
{
	char output[1024];
	char *command[] = { "wlif-runtime", NULL, NULL, NULL };
	int status, inherited;
	long long started;
	if (argc > 1) {
		if (!strcmp(argv[1], "exit7"))
			return 7;
		if (!strcmp(argv[1], "signal")) {
			raise(SIGTERM);
			return 99;
		}
		if (!strcmp(argv[1], "echo")) {
			assert(argc == 3);
			printf("%s", argv[2]);
			return 0;
		}
		if (!strcmp(argv[1], "fd")) {
			errno = 0;
			return fcntl(atoi(argv[2]), F_GETFD) == -1 && errno == EBADF ? 0 : 98;
		}
		if (!strcmp(argv[1], "hang")) {
			signal(SIGALRM, SIG_IGN);
			for (;;)
				pause();
		}
		if (!strcmp(argv[1], "overflow")) {
			memset(output, 'x', sizeof(output));
			assert(write(STDOUT_FILENO, output, sizeof(output)) == sizeof(output));
			return 0;
		}
		if (!strcmp(argv[1], "fdhold")) {
			if (fork() == 0)
				for (;;)
					pause();
			return 0;
		}
		return 97;
	}
	/* Adopt/reap the deliberate pipe-holding grandchild in this fixture. */
	assert(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
	command[1] = "exit7";
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
	command[1] = "signal";
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
	command[1] = "echo";
	command[2] = "SSID ' \" $() ; `cmd` \\ spaces";
	assert(wl_wlif_run_argv(command, output, sizeof(output)) == 0);
	assert(!strcmp(output, command[2]));
	command[2] = NULL;
	command[1] = "overflow";
	errno = 0;
	assert(wl_wlif_run_argv(command, output, sizeof(output)) == -1);
	assert(errno == EOVERFLOW && output[0] == '\0');
	check_reaped();
	command[1] = "hang";
	started = wl_wlif_milliseconds();
	assert(wl_wlif_run_argv(command, output, sizeof(output)) == -1);
	assert(errno == ETIMEDOUT && output[0] == '\0');
	assert(wl_wlif_milliseconds() - started < 1500);
	check_reaped();
	command[1] = "fdhold";
	assert(wl_wlif_run_argv(command, output, sizeof(output)) == -1);
	assert(errno == ETIMEDOUT && output[0] == '\0');
	assert(waitpid(-1, &status, 0) > 0);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	check_reaped();
	inherited = open("/dev/null", O_RDONLY);
	assert(inherited >= 0);
	/* Sparse high descriptor catches both leaks and million-entry scans. */
	status = fcntl(inherited, F_DUPFD, 65536);
	if (status >= 0) {
		close(inherited);
		inherited = status;
	}
	snprintf(output, sizeof(output), "%d", inherited);
	command[1] = "fd";
	command[2] = output;
	assert(wl_wlif_run_argv(command, NULL, 0) == 0);
	close(inherited);
	command[0] = "wlif-no-such-command";
	command[1] = NULL;
	command[2] = NULL;
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 127);
	/* execvp would pass this executable text to /bin/sh. */
	inherited = open(WLIF_TEST_DIR "/wlif-text", O_CREAT | O_WRONLY | O_EXCL, 0700);
	assert(inherited >= 0);
	assert(write(inherited, "exit 0\n", 7) == 7);
	close(inherited);
	command[0] = "wlif-text";
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 127);
	check_reaped();
	puts("wlif runtime: raw status, argv, timeout, overflow, reaping, FD closure, ENOEXEC passed");
	return 0;
}
