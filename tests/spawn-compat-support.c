#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <stddef.h>

static sigset_t saved_mask;
static int mask_saved;

/* Save the current mask and make manager startup inherit one blocked signal. */
int spawn_test_block_signal(void)
{
	sigset_t mask;

	if (mask_saved) {
		return EALREADY;
	}
	if (sigprocmask(SIG_SETMASK, NULL, &saved_mask) < 0) {
		return errno;
	}
	if (sigemptyset(&mask) < 0 || sigaddset(&mask, SIGUSR1) < 0) {
		return errno;
	}
	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		return errno;
	}
	mask_saved = 1;
	return 0;
}

/* Restore the exact caller mask after the manager-inheritance assertion. */
int spawn_test_restore_signal_mask(void)
{
	if (!mask_saved) {
		return EINVAL;
	}
	if (sigprocmask(SIG_SETMASK, &saved_mask, NULL) < 0) {
		return errno;
	}
	mask_saved = 0;
	return 0;
}
