#ifndef __UTIL_H__
#define __UTIL_H__
/*
 * A util api for string and cmdline processing
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// system errors
#define UTIL_OK    0
#define UTIL_FAIL -1
#define UTIL_EOF  -2

// general purpose macros
#define ARR_LEN(a) (sizeof(a) / sizeof(a[0]))
#define ARRAY(a) ARR_LEN(a), a
#define STR_LIT(s) (s), (sizeof(s) - 1)
#define containerof(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define make_ptr(ptr, offset) ((void *) (ptr + offset))
#define make_cptr(ptr, offset) ((char *) (ptr + offset))
#define ALIGN_UP(n, a) (((n) + (a) - 1) & ~((a) - 1))

// Stringification macros
#define XSTR(a) #a
#define STR(a) XSTR(a)

// return str if set else use default
static inline const char *str_def(const char *str, const char *def_str)
{
    return str && *str ? str : def_str;
}

static inline size_t max(size_t x, size_t y)
{
    return x > y ? x : y;
}

static inline const char *ec_tostr(int len, const char *estr[len], int ec, const char *def)
{
    const char *str;

    str = ec >= 0 && ec < len
        ? estr[ec] 
        : NULL;

    return str ?: def;
}

// buffer code
struct rwbuf {
    char *data;
    int cap; // fixed size 
    int widx;  // start of bytes to read
    int ridx;
};

static inline void rwbuf_init(struct rwbuf *buf, char *data, int len)
{
    buf->data = data;
    buf->cap = len;
    buf->widx = 0;
    buf->ridx = 0;
}

#define RWBUF_INIT(_buf, _len) { .data = (_buf), .cap = (_len), .widx = 0, .ridx = 0 }


static inline char *rwbuf_wpos(struct rwbuf *buf)
{
    return buf->data + buf->widx;
}

static inline int rwbuf_wrem(struct rwbuf *buf)
{
    return buf->cap - buf->widx;
}

// bytes writen to buffer available to read
static inline int rwbuf_avail(struct rwbuf *buf)
{
    return buf->widx - buf->ridx;
}

static inline char *rwbuf_rpos(struct rwbuf *buf)
{
    return buf->data + buf->ridx;
}

static inline int rwbuf_rrem(struct rwbuf *buf)
{
    return buf->widx - buf->ridx;
}

// resever len bytes in buf or error
static inline char *rwbuf_wres(struct rwbuf *buf, int len)
{
    int wrem = buf->cap - buf->widx;

    if (wrem < len) {
        // not enough space
        return  NULL;
    }

    char *wptr = buf->data + buf->widx;
    buf->widx += len;

    return wptr;
}

static inline char *rwbuf_strcat(struct rwbuf *buf, const char *str, int len)
{
    char *wptr = rwbuf_wres(buf, len);

    if (wptr) {
        memcpy(wptr, str, len);
    }

    return wptr;
}

static inline char *rwbuf_strcat_sep(struct rwbuf *buf, int ch, const char *str, int len)
{
    int add_ch = (buf->widx > 0) ? 1 : 0;
    char *wptr = rwbuf_wres(buf, len + add_ch);

    if (wptr) {
        if (add_ch) *wptr++ = ch;
        memcpy(wptr, str, len);
    }

    return wptr;
}




// logger
void log_msg(const char *msg);
void log_info(const char *what, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
int log_cmd_err(const char *cmd, const char *opt, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
void _log_error(const char *file, int line, const char *func, int ec, const char *fmt, ...) 
    __attribute__((format(printf, 5, 6)));
void _fatal_error(const char *file, int line, const char *func, int ec, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

#define log_msg_rf(msg) ({ \
    log_msg(msg); \
    UTIL_FAIL; \
})

// report msg, return 0
#define log_info_rz(what, ...) ({ \
    log_info(what,  __VA_ARGS__); \
    UTIL_OK; \
})

// report estr
#define log_error(...) \
    _log_error(__FILE__, __LINE__, __func__, 0, __VA_ARGS__)

// report estr, return FAIL
#define log_error_rf(...) ({ \
    _log_error(__FILE__, __LINE__, __func__, 0,  __VA_ARGS__); \
    UTIL_FAIL; \
})

// report estr, return 0
#define log_error_rz(...) ({ \
    _log_error(__FILE__, __LINE__, __func__, 0,  __VA_ARGS__); \
    UTIL_OK; \
})

// report estr, return NULL
#define log_error_rn(...) ({ \
    _log_error(__FILE__, __LINE__, __func__, 0,  __VA_ARGS__); \
    (void *) NULL; \
})

// report errno + estr
#define log_errno(...) \
    _log_error(__FILE__, __LINE__, __func__, errno,  __VA_ARGS__)

// report errno + estr, return NULL
#define log_errno_rn(...) ({ \
    _log_error(__FILE__, __LINE__, __func__, errno,  __VA_ARGS__); \
    (void *) NULL; \
})

// report errno + estr, return ec
#define log_errno_re(ec, ...) ({ \
    _log_error(__FILE__, __LINE__, __func__, errno,  __VA_ARGS__); \
    (ec); \
})

// report errno + estr, return FAIL
#define log_errno_rf(...) ({ \
    _log_error(__FILE__, __LINE__, __func__, errno,  __VA_ARGS__); \
    UTIL_FAIL; \
})


#define fatal_error(...) _fatal_error(__FILE__, __LINE__, __func__, 0,  __VA_ARGS__)
#define fatal_errno(...) _fatal_error(__FILE__, __LINE__, __func__, errno,  __VA_ARGS__)
#define log_errorn(...) (log_error(__VA_ARGS__), (void*)NULL)
#define log_debug(fmt, ...) { fprintf(stderr, fmt, ##__VA_ARGS__); fprintf(stderr, "\n"); }

// string handling code
struct str_slice {
    char *ptr;
    size_t len;
};

#define SLICE(x) (int) (x).len, (x).ptr

static inline struct str_slice slice_make(char *str, size_t len)
{
    struct str_slice dst;

    dst.ptr = str;
    dst.len = len;

    return dst;
}

static inline struct str_slice slice_make_cstr(char *str)
{
    return slice_make(str, str ? strlen(str) : 0);
}

static inline struct str_slice slice_copy(struct str_slice val)
{
    return val;
}

static inline int slice_cmp_cstr(struct str_slice str, const char *cstr, int len)
{
    return len == str.len && memcmp(str.ptr, cstr, len) == 0;
}

static inline struct str_slice slice_rsplit(struct str_slice *src, int ch)
{
    struct str_slice dst;
   
    dst.ptr = memrchr(src->ptr, ch, src->len);

    if (dst.ptr) {
        dst.len = src->len - (dst.ptr - src->ptr + 1);
        src->len -= dst.len + 1;
        dst.ptr++;
    }
    else {
        dst.len = 0;
    }

    return dst;
}

static inline struct str_slice slice_split(struct str_slice *src, int ch)
{
    struct str_slice dst;
   
    char *ptr = memchr(src->ptr, ch, src->len);

    if (ptr) {
        // split on ch
        dst.ptr = src->ptr;
        dst.len = ptr - src->ptr;
        src->ptr = ptr + 1;
        src->len -= dst.len + 1;
    }
    else {
        // take it all
        dst.ptr = src->ptr;
        dst.len = src->len;
        src->ptr = NULL;
        src->len = 0;
    }

    return dst;
}

static inline struct str_slice slice_rsplit1(struct str_slice src, int ch)
{
    struct str_slice dst;

    dst.ptr = memrchr(src.ptr, ch, src.len);

    if (dst.ptr) {
        dst.len = src.len - (dst.ptr - src.ptr + 1);
        dst.ptr++;
    }
    else {
        dst.ptr = src.ptr;
        dst.len = src.len;
    }

    return dst;
}

static inline struct str_slice slice_lsplit1(struct str_slice src, int ch)
{
    struct str_slice dst;

    dst.ptr = memchr(src.ptr, ch, src.len);

    if (dst.ptr) {
        dst.len = src.len - (dst.ptr - src.ptr + 1);
    }
    else {
        dst.len = src.len;
    }
    dst.ptr = src.ptr;

    return dst;
}

char *slice_strdup(const struct str_slice str);

static inline void str_tolower(char *str, size_t len)
{
    while (len) {
        int ch = *str;
        if (ch >= 'A' && ch <= 'Z') ch += 0x20;
        *str++ = ch;
        len--;
    }
}

static inline void str_toupper(char *str, size_t len)
{
    while (len) {
        int ch = *str;
        if (ch >= 'a' && ch <= 'z') ch -= 0x20;
        *str++ = ch;
        len--;
    }
}

char *itoa(char *buf, int len, int val);
char *int_tostr(int val);

static inline int iswhite(int ch) 
{
    return ch == ' ' || ch == '\t' || ch == '\v' || ch == '\r' || ch == '\t' ? 1 : 0;
}

static inline int is_numeral(int ch) 
{
    return ch >= '0' && ch <= '9' ? 1 : 0;
}


static inline int str_isnumeric(const char *str, size_t len)
{
	if (!len) return 0;
    
    const char *end = str + len;

    while (str < end) {
        if (!is_numeral(*str)) return 0;
        str++;
    }

    return 1;
}

static inline int slice_isnumeric(struct str_slice str)
{
    return str_isnumeric(str.ptr, str.len);

}

static inline struct str_slice *slice_ltrim(struct str_slice *str)
{
    while (str->len && iswhite(*str->ptr)) {
        str->ptr++;
        str->len--;
    }

    return str;
}

static inline struct str_slice *slice_rtrim(struct str_slice *str)
{
    while (str->len && iswhite(str->ptr[str->len - 1])) {
        str->len--;
    }

    return str;
}

static inline struct str_slice *slice_trim(struct str_slice *str)
{
    return slice_ltrim(slice_rtrim(str));
}

static inline struct str_slice slice_toupper(struct str_slice str)
{
    str_toupper(str.ptr, str.len);

    return str;
}

static inline struct str_slice slice_tolower(struct str_slice str)
{
    str_tolower(str.ptr, str.len);

    return str;
}

struct util_cmd {
    const char *name;
    size_t len;
    int (*func)(void *state, int narg, struct str_slice args[]);
};

int util_parse_argv(void *state,
    int argc, char *argv[],
    int ncmd, struct util_cmd cmds[ncmd],
    int (*usage_func)(void *state, struct str_slice prog));

char *gen_path(const char *dir, const char *name);

//  djb2a hash algorhtim
static inline uint64_t dbj2a_hash(const void *key, const int klen)
{
    const unsigned char *data,*end;
    uint64_t hash = 5381;

    end = key + klen;
    for (data = key; data < end; data++) {
        hash = ((hash << 5) + hash) ^ *data;
    }

    return hash;
}

static inline uint64_t dbj2a_hash_str(const char *name)
{
    return dbj2a_hash(name, strlen(name));
}

static inline uint64_t dbj2a_hash_slice(const struct str_slice str)
{
    return dbj2a_hash(str.ptr, str.len);
}

#endif
