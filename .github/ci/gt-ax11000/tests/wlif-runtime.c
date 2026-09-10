/* Linked to the actual wrapper; the actual standalone helper owns the CLI. */
#include "wlif_process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <limits.h>

#ifdef WLIF_FIXTURE_QEMU
/* Native exec bridge only: binfmt registration is deliberately unnecessary.
 * The helper and CLI algorithms still execute in the compiled ARM binaries. */
int main(int argc, char **argv)
{
	char executable[PATH_MAX];
	char **args = calloc((size_t)argc + 6, sizeof(*args));
	ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 5);
	int i;
	assert(args && length > 0);
	executable[length] = '\0';
	if (!strcmp(strrchr(executable, '/') + 1, "hostapd_cli"))
		assert(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
	memcpy(executable + length, ".arm", 5);
	args[0] = WLIF_FIXTURE_QEMU;
	args[1] = "-L";
	args[2] = WLIF_FIXTURE_SYSROOT;
	args[3] = executable;
	for (i = 1; i < argc; i++) args[i + 3] = argv[i];
	execv(args[0], args);
	perror("qemu fixture exec");
	return 127;
}
#else

static atomic_int reaper_stop, reaper_count;
static int atfork_called;
static void forbidden_atfork(void) { atfork_called++; }

static void *foreign_reaper(void *unused)
{
	int status;
	(void)unused;
	while (!atomic_load(&reaper_stop)) {
		if (waitpid(-1, &status, WNOHANG) > 0)
			atomic_fetch_add(&reaper_count, 1);
		else
			sched_yield();
	}
	return NULL;
}

static void reap_fixture_children(void)
{
	int status;
	while (waitpid(-1, &status, 0) > 0 || errno == EINTR)
		;
	assert(errno == ECHILD);
}

static void check_reaped(void)
{
	int status;
	errno = 0;
	assert(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
}

int main(int argc, char **argv)
{
	char output[1024];
	char *command[] = { "hostapd_cli", NULL, NULL, NULL };
	int status, inherited;
	long long started;
	/* The test temporarily substitutes this executable for its private
	 * helper, exercising IPC validation without mocking the caller. */
	if (getenv("WLIF_FIXTURE_REPLY")) {
		const char *mode = getenv("WLIF_FIXTURE_REPLY");
		struct wlif_process_reply reply = { WLIF_REPLY_MAGIC, 0, 0, 0 };
		size_t length = sizeof(reply);
		if (!strcmp(mode, "magic")) reply.magic = 0;
		if (!strcmp(mode, "header")) length--;
		if (!strcmp(mode, "length")) reply.length = WLIF_CAPTURE_MAX;
		if (!strcmp(mode, "body")) reply.length = 4;
		if (!strcmp(mode, "group"))
			reply.status = getpgrp() == (pid_t)atoi(getenv("WLIF_FIXTURE_PARENT_GROUP")) ? 256 : 0;
		assert(write(1, &reply, length) == (ssize_t)length);
		return 0;
	}
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
		if (!strcmp(argv[1], "signals")) {
			sigset_t mask;
			struct sigaction action;
			assert(sigprocmask(SIG_SETMASK, NULL, &mask) == 0);
			assert(!sigismember(&mask, SIGTERM));
			assert(!sigismember(&mask, SIGCHLD));
			assert(sigaction(SIGCHLD, NULL, &action) == 0);
			assert(action.sa_handler == SIG_DFL);
			return 0;
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
		if (!strcmp(argv[1], "fdshort")) {
			/* Holds stdout past the deadline, then exits by itself. */
			if (fork() == 0) {
				struct timespec nap = { 0, 400000000 };
				nanosleep(&nap, NULL);
				_exit(0);
			}
			return 5;
		}
		return 97;
	}
	/* Adopt/reap the deliberate pipe-holding grandchild in this fixture. */
#ifdef WLIF_FIXTURE_UNDER_QEMU
	/* QEMU-user does not implement this prctl; the native exec bridge has
	 * already set the kernel attribute, which survives exec. */
#else
	assert(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
#endif
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
	/* A descendant holding stdout must not stall a caller that captures
	 * nothing.  wl_wlif_wps_pbc_hdlr and wl_wlif_wps_stop_session pass
	 * output == NULL, where the vendor used system() and opened no pipe;
	 * waiting for pipe EOF there turned a WPS button press into a full
	 * WLIF_CLI_TIMEOUT_MS freeze and discarded the child's real status.
	 */
	command[1] = "fdshort";
	started = wl_wlif_milliseconds();
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 5);
	assert(wl_wlif_milliseconds() - started < 1500);
	/* The grandchild outlives the call and must not have been signalled. */
	assert(waitpid(-1, &status, WNOHANG) == 0);
	assert(waitpid(-1, &status, 0) > 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	check_reaped();
	/* Capture must wait for EOF even after the CLI exits. The helper still
	 * owns the unreaped CLI PID while killing its pipe-holding descendant. */
	command[1] = "fdshort";
	started = wl_wlif_milliseconds();
	assert(wl_wlif_run_argv(command, output, sizeof(output)) == -1);
	assert(errno == ETIMEDOUT && output[0] == '\0');
	assert(wl_wlif_milliseconds() - started < 1500);
	assert(waitpid(-1, &status, 0) > 0);
	assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
	check_reaped();
	/* The caller may discard helper wait status: CLI status travels over
	 * IPC, and only the fresh helper owns/reaps/signals the actual CLI. */
	assert(signal(SIGCHLD, SIG_IGN) != SIG_ERR);
	command[1] = "exit7";
	errno = 0;
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
	{
		sigset_t mask, saved;
		sigemptyset(&mask);
		sigaddset(&mask, SIGCHLD);
		sigaddset(&mask, SIGTERM);
		assert(sigprocmask(SIG_BLOCK, &mask, &saved) == 0);
		command[1] = "signals";
		assert(wl_wlif_run_argv(command, NULL, 0) == 0);
		command[1] = "signal";
		status = wl_wlif_run_argv(command, NULL, 0);
		assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
		assert(sigprocmask(SIG_SETMASK, &saved, NULL) == 0);
	}
	assert(signal(SIGCHLD, SIG_DFL) != SIG_ERR);
	check_reaped();
	{
		pthread_t reaper;
		pid_t sentinel;
		int i;
		assert(pthread_create(&reaper, NULL, foreign_reaper, NULL) == 0);
		sentinel = fork();
		assert(sentinel >= 0);
		if (!sentinel) _exit(0);
		command[1] = "exit7";
		for (i = 0; i < 48; i++) {
			status = wl_wlif_run_argv(command, NULL, 0);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
		}
		atomic_store(&reaper_stop, 1);
		assert(pthread_join(reaper, NULL) == 0);
		assert(atomic_load(&reaper_count) > 0);
		reap_fixture_children();
	}
	{
		int saved_input = dup(0), saved_output = dup(1);
		assert(saved_input >= 0 && saved_output >= 0);
		close(0);
		close(1);
		command[1] = "echo";
		command[2] = "closed standard descriptors";
		status = wl_wlif_run_argv(command, output, sizeof(output));
		assert(dup2(saved_input, 0) == 0 && dup2(saved_output, 1) == 1);
		close(saved_input);
		close(saved_output);
		if (status != 0 || strcmp(output, command[2]))
			fprintf(stderr, "closed-FD capture: status=%d errno=%d output='%s'\n", status, errno, output);
		assert(status == 0 && !strcmp(output, command[2]));
		command[2] = NULL;
	}
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
	command[0] = "wpa_cli";
	command[1] = NULL;
	command[2] = NULL;
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 127);
	/* execvp would pass this executable text to /bin/sh. */
	inherited = open(WLIF_TEST_DIR "/wpa_cli", O_CREAT | O_WRONLY | O_EXCL, 0700);
	assert(inherited >= 0);
	assert(write(inherited, "exit 0\n", 7) == 7);
	close(inherited);
	command[0] = "wpa_cli";
	status = wl_wlif_run_argv(command, NULL, 0);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 127);
	check_reaped();
	/* A library call inside a multithreaded daemon must not execute its
	 * process-wide fork callbacks. Register after fixture-owned forks. */
	assert(pthread_atfork(forbidden_atfork, NULL, NULL) == 0);
	command[0] = "hostapd_cli";
	command[1] = "exit7";
	assert(wl_wlif_run_argv(command, NULL, 0) == (7 << 8));
	assert(atfork_called == 0);
	assert(rename(WLIF_TEST_DIR "/wlif-exec", WLIF_TEST_DIR "/wlif-exec.saved") == 0);
	command[0] = "hostapd_cli";
	command[1] = "exit7";
	assert(wl_wlif_run_argv(command, output, sizeof(output)) == -1);
	/* Native spawn reports ENOENT directly; a failed-exec child observed
	 * through the QEMU exec bridge may instead close IPC and report EIO.
	 * Neither may become success or expose stale captured output. */
	assert((errno == ENOENT || errno == EIO) && output[0] == '\0');
	reap_fixture_children();
	assert(symlink(WLIF_TEST_DIR "/hostapd_cli", WLIF_TEST_DIR "/wlif-exec") == 0);
	snprintf(output, sizeof(output), "%ld", (long)getpgrp());
	assert(setenv("WLIF_FIXTURE_PARENT_GROUP", output, 1) == 0);
	assert(setenv("WLIF_FIXTURE_REPLY", "group", 1) == 0);
	assert(wl_wlif_run_argv(command, NULL, 0) == 0);
	assert(unsetenv("WLIF_FIXTURE_PARENT_GROUP") == 0);
	{
		const char *modes[] = { "magic", "header", "length", "body" };
		size_t i;
		for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
			assert(setenv("WLIF_FIXTURE_REPLY", modes[i], 1) == 0);
			assert(wl_wlif_run_argv(command, output, sizeof(output)) == -1);
			assert(errno == ((!strcmp(modes[i], "magic") || !strcmp(modes[i], "length")) ? EPROTO : EIO));
			assert(output[0] == '\0');
			reap_fixture_children();
		}
		assert(unsetenv("WLIF_FIXTURE_REPLY") == 0);
	}
	assert(unlink(WLIF_TEST_DIR "/wlif-exec") == 0);
	assert(rename(WLIF_TEST_DIR "/wlif-exec.saved", WLIF_TEST_DIR "/wlif-exec") == 0);
	puts("wlif runtime: status, argv, timeout, overflow, capture descendants,\n             foreign reaper, signals, closed FDs, atfork, helper group, IPC, ENOEXEC passed");
	return 0;
}
#endif
