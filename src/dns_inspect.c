/*
 * dns-inpect - a simple DNS packet sniffer
 *
 * Usage: dns-inspect
 *
 * Notes:
 *
 */
#include <stdio.h>
#include <stdlib.h> 
#include <stdarg.h>
#include <stddef.h>
#include <string.h> 
#include <signal.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h> 
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>

#include "util.h"

#define MODE_CAPTURE 1

struct dns_sniff {
    // config
    pid_t pid;
    char *host;
	char *port;
	//  state
    int mode;
    char dev_name[IFNAMSIZ]; 
};

// signal handling
volatile sig_atomic_t keep_running = 1;
volatile sig_atomic_t caught_signo = 0; 
volatile sig_atomic_t sender_pid = 0; 
volatile sig_atomic_t sender_uid = 0; 

void sniff_handle_signal(int signo, siginfo_t *info, void *ucontext)
{
    caught_signo = signo;

    sender_pid = 0;
    sender_uid = 0;

    if (info->si_code <= 0) {
        sender_pid = info->si_pid;
        sender_uid = info->si_uid;
    }

    keep_running = 0;
}

int sniff_signals(struct dns_sniff *sniff)
{
    struct sigaction sa = { 0 };

    sa.sa_sigaction = sniff_handle_signal;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        return log_errno("setup sigint");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        return log_errno("setup sigterm");
    }

    // XXX prevent write(fd) trigger a signal
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        return log_errno("setup SIGPIPE");
    }

    return 0;
}

int sniff_run(struct dns_sniff *sniff)
{
    return 0;
}

static int sniff_usage(struct dns_sniff *sniff, const char *cmd)
{
	const char *base = strrchr(cmd, '/');
	const char *prog_name = (base) ? base + 1 : cmd;
    FILE *out = stderr;
	int w= 10;

    fprintf(out,"Usage: %s [MODE] [OPTIONS]\n\n" , prog_name);

    fprintf(out, "MODE:\n");
	fprintf(out, "  %-*s %s\n", w, "--help", "Show this help");
	fprintf(out, "  %-*s %s\n", w, "capture", "--interface name");

    fprintf(out, "\nExample:\n");
    fprintf(out, "  %s capture --interface eth0\n", prog_name);

    return -1;
}

// dns-inspect capture --interface eth0
int sniff_parse_argv(struct dns_sniff *sniff, int argc, char *argv[])
{
    if (argc < 2) {
        return sniff_usage(sniff, argv[0]);
    }

    // mode
	struct str_slice mode = slice_make_cstr(argv[1]);
    if (slice_cmp_cstr(mode, STR_LIT("capture"))) {
        sniff->mode = MODE_CAPTURE;
        int nargs = argc - 2;
        if (nargs != 2) {
           return log_error("capture require an --interface name");
        }
        // --interface option
		struct str_slice opt = slice_make_cstr(argv[2]);
		struct str_slice val = slice_make_cstr(argv[3]);
        if (!slice_cmp_cstr(opt, STR_LIT("--interface"))) {
           return log_error("capture unknown option %s", opt.ptr);
        }
        if (opt.len >= sizeof(sniff->dev_name)) {
           return log_errno("dev-name too big - cant be bigger than", sizeof(sniff->dev_name) - 1);
        }
        memcpy(sniff->dev_name, val.ptr, val.len);
        sniff->dev_name[val.len] = '\0';
    }
    else {
        log_error("Unsupported mode %s", mode.ptr);
        return sniff_usage(sniff, argv[0]);
    }

    return 0;
}

void sniff_free(struct dns_sniff *sniff)
{
    free(sniff);
}

static int sniff_init(struct dns_sniff *sniff)
{
    memset(sniff, 0, sizeof(*sniff));

    return 0;
}

struct dns_sniff *sniff_create(void)
{
    struct dns_sniff *sniff;

    sniff = malloc(sizeof(*sniff));
    if (!sniff) {
        return log_errnon("Malloc failed for sniff state");
    }

    return sniff;
}

int main(int argc, char *argv[])
{
    struct dns_sniff *sniff = NULL;
    int ec = EXIT_FAILURE;

    if (!(sniff = sniff_create())) { ec = 1; goto done; }
    if (sniff_init(sniff) != 0)    { ec = 3; goto done; }
    if (sniff_parse_argv(sniff, argc, argv) != 0) { ec = 4;  goto done; }
    if (sniff_signals(sniff) != 0)  { ec = 2 ;goto done; }
    if (sniff_run(sniff) != 0) { ec = 7; goto done; }

    if (caught_signo) {
        log_info("[dns-sniff PID:%d] shutting down: got signal %d (%s) from UID:%d PID:%d ", 
            sniff->pid, 
            caught_signo, strsignal(caught_signo), 
            sender_uid,
            sender_pid);
    }

    // all done
    ec = 0;

done:
    if (sniff) sniff_free(sniff);

    return ec;
}
