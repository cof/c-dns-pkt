/*
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "util.h"

void log_msg(const char *msg)
{
    fputs(msg, stdout);
    fflush(stdout);
}

void log_info(const char *what, const char *fmt, ...)
{
    va_list args;  

    fprintf(stdout, "[%s] ", what);

    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fprintf(stdout, "\n");
}

int log_cmd_err(const char *cmd, const char *opt, const char *fmt, ...)
{
    va_list args;  

    fprintf(stdout, "[ERROR] %s: %s: ", cmd, opt);

    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fprintf(stdout, "\n");
    
    return -1;
}

void _log_error(const char *file, int line, const char *func, int ec, const char *fmt, ...)
{
    va_list args;  

    fprintf(stderr, "[ERROR] %s:%d (%s): ", file, line, func);

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    if (ec != 0) {
        // have an errno
        fprintf(stderr, ": %s (errno: %d)", strerror(ec), ec);
    }

    fprintf(stderr, "\n");
}

void _fatal_error(const char *file, int line, const char *func, int ec, const char *fmt, ...)
{
    va_list args;  

    fprintf(stderr, "[FATAL] %s:%d (%s): ", file, line, func);

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    if (ec != 0) {
        fprintf(stderr, ": %s (errno: %d)", strerror(ec), ec);
    }

    fprintf(stderr, "\n");
    fflush(stderr);

    exit(1);
}

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
