/*
 * dns-gen - a simple DNS packet generator
 *
 * Usage: dns-gen
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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h> 
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>

#include "util.h"

// supported cmds
#define MODE_QUERY 1
#define MODE_FUZZ  2
#define MODE_RESP  3

struct dns_gen {
    // config
    pid_t pid;
	//  state
    int mode;
};

// signal handling
static volatile sig_atomic_t keep_running = 1;
static volatile sig_atomic_t caught_signo = 0; 
static volatile sig_atomic_t sender_pid = 0; 
static volatile sig_atomic_t sender_uid = 0; 

static void catch_signal(int signo, siginfo_t *info, void *ucontext)
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

int gen_signals(struct dns_gen *gen)
{
    struct sigaction sa = { 0 };

    sa.sa_sigaction = catch_signal;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        return log_errno_rf("setup sigint");
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        return log_errno_rf("setup sigterm");
    }

    // XXX prevent write(fd) trigger a signal
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        return log_errno_rf("setup SIGPIPE");
    }

    return 0;
}

static int gen_setup_fuzz(void *state, int narg, struct str_slice args[])
{
    return -1;
}

static int gen_setup_resp(void *state, int narg, struct str_slice args[])
{
    return -1;
}

static int gen_setup_query(void *state, int narg, struct str_slice args[])
{
    return 0;
}

static int gen_usage(void *state, struct str_slice prog_name)
{
    FILE *out = stderr;
    int w= 10;

    fprintf(out,"Usage: %.*s [MODE] [OPTIONS]\n\n", SLICE(prog_name));

    fprintf(out, "MODE:\n");
    fprintf(out, "  %-*s %s\n", w, "query", "--name <dns-name> --type <rec-type> --server <ip-addr> --tcp");
    fprintf(out, "  %-*s %s\n", w, "fuzz", "--type <rec-type> --server <ip-addr>");
    fprintf(out, "  %-*s %s\n", w, "response", "--id <trans-id> --name <dns-name> --answer <ip-addr> --output <pcap-file>");

    fprintf(out, "\nExample:\n");
    fprintf(out, "  %.*s query --name example.com --type A --server 8.8.8.8\n", SLICE(prog_name));
    fprintf(out, "  %.*s fuzz --type compression-loop --server 127.0.0.1\n", SLICE(prog_name));
    fprintf(out, "  %.*s response --id 0x1234 --name test.local --answer 192.168.1.1 --output packet.bin\n", SLICE(prog_name));

    return -1;
}

static struct util_cmd cmds[] =  {
    { STR_LIT("query"), gen_setup_query },
    { STR_LIT("fuzz"),  gen_setup_fuzz },
    { STR_LIT("response"),  gen_setup_resp },
};

static int gen_parse_argv(struct dns_gen *gen, int argc, char *argv[])
{
    return util_parse_argv(gen, argc, argv, ARRAY(cmds), gen_usage);
}

void gen_free(struct dns_gen *gen)
{
    free(gen);
}

static int gen_init(struct dns_gen *gen)
{
    memset(gen, 0, sizeof(*gen));

    return 0;
}

struct dns_gen *gen_create(void)
{
    struct dns_gen *gen;

    gen = malloc(sizeof(*gen));
    if (!gen) {
        return log_errno_rn("Malloc failed for gen state");
    }

    return gen;
}

int main(int argc, char *argv[])
{
    struct dns_gen *gen = NULL;
    int ec = EXIT_FAILURE;

    if (!(gen = gen_create())) { ec = 1; goto done; }
    if (gen_init(gen) != 0)    { ec = 3; goto done; }
    if (gen_signals(gen) != 0)  { ec = 2 ;goto done; }
    if (gen_parse_argv(gen, argc, argv) != 0) { ec = 4;  goto done; }

    switch(gen->mode) {
    case MODE_QUERY:
        break;
    }
    // all done
    ec = 0;

done:
    if (gen) gen_free(gen);

    return ec;
}
