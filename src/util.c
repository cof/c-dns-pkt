/*
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "util.h"
#include "log.h"

char *gen_path(const char *dir, const char *name)
{
    if (!dir || !name) return NULL;

    char *path = NULL;
    int rc = asprintf(&path, "%s/%s", dir, name);

    if (rc == -1) {
        // out of memory ?
        return NULL;
    }

    return path;
}

char *slice_strdup(const struct str_slice str)
{
    char *copy = malloc(str.len + 1);

    if (copy) {
        memcpy(copy, str.ptr, str.len);
        copy[str.len] = 0;
    }

    return copy;
}

char *itoa(char *buf, int len, int val)
{
    if (!buf || len == 0) {
        return buf;
    }

    char *str = &buf[len -1];
    *str = '\0';
    if (val == 0) *--str = '0';

    while (val) {
        *--str = (val % 10) + '0';
        val /= 10;
    }

    return str; 
}

char *int_tostr(int val) 
{
    static char bufs[16][10];
    static int idx;

    char *str = bufs[idx];
    idx = (idx + 1) & 15;

    return itoa(str, sizeof(bufs[0][0]), val);
}

int getopt_init(struct getopt_parse *parse, 
    int argc, char *argv[],
    size_t num_opt, struct get_opt opts[num_opt])
{
    memset(parse->long_opts, 0, sizeof(parse->long_opts));

    parse->argc = argc;
    parse->argv = argv;

    parse->opts = opts;
    parse->num_opt = num_opt;

    if (num_opt > GETOPT_MAX) {
        return log_error_rf("Num opts %zu > max %d", num_opt, GETOPT_MAX);
    }

    for (size_t i = 0; i < num_opt; i++) {
        struct option *long_opt = &parse->long_opts[i];
        long_opt->name = opts[i].name;
        long_opt->has_arg = opts[i].has_arg;
        long_opt->val = opts[i].val;
    }

    return 0;
}

int getopt_next(struct getopt_parse *parse)
{
    int rc = getopt_long_only(
        parse->argc, parse->argv,
        "", parse->long_opts, 
        &parse->opt_idx
    );

    if (rc == -1) return rc;
    if (rc == '?' || rc == ':') {
        parse->opt_idx = optind -1;
        return rc;
    }
    
    parse->val = slice_make_cstr(optarg);
    
    return rc;
}

void print_usage(const char *cmd, 
    int num_opt, const struct get_opt opts[num_opt],
    int num_exa, char *examples[num_exa])
{
    const char *base = strrchr(cmd, '/');
    const char *prog_name = (base) ? base + 1 : cmd;
    int w= 15;

    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");

    for (int i = 0; i < num_opt; i++) {
        printf(" --%-*s %s", w, opts[i].name, opts[i].desc);
        if (opts[i].have_defval) {
            printf(" (default=%d)", opts[i].def_val);
        }
        printf("\n");
    }

    if (!num_exa) return;

    printf("\nExamples:\n");
    for (int i = 0; i < num_exa; i++) {
        printf("  %s %s\n", prog_name, examples[i]);
    }
}

static int find_cmd(struct str_slice cmd, int ncmd, struct util_cmd cmds[ncmd])
{
    cmd = slice_tolower(cmd);

    for (int i = 0; i < ncmd; i++) {
        if (slice_cmp_cstr(cmd, cmds[i].name, cmds[i].len)) {
            return i;
        }
    }

    return -1;
}

int util_parse_argv(void *state,
    int argc, char *argv[],
    int ncmd, struct util_cmd cmds[ncmd],
    int (*usage_func)(void *state, struct str_slice prog))
{
    // mode
    struct str_slice mode = slice_make_cstr(argv[1]);
    int cmd_idx = find_cmd(mode, ncmd, cmds);

    if (argc < 2) {
        if (usage_func) {
            return usage_func(state, slice_rsplit1(slice_make_cstr(argv[0]), '/'));
        }
        // fail
        return -1;
    }

    if (cmd_idx == -1) {
        log_error_rf("Unsupported mode %.*s", (int) mode.len, mode.ptr);
        if (usage_func) {
            return usage_func(state, slice_rsplit1(slice_make_cstr(argv[0]), '/'));
        }
        // fail
        return -1;
    }

    // load remaing args
    int len = argc - 2;
    struct str_slice args[len];
    for (int i = 0; i < len; i++) {
        args[i] = slice_make_cstr(argv[i + 2]);
    }

    return cmds[cmd_idx].func(state, len, args);
}
