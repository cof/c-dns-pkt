/*
 * A simple string write buffer
 */
#ifndef _STRBUF_H_
#define _STRBUF_H_

struct strbuf {
    char *data;
    char *wptr;
    char *end;
};

#define STRBUF_INIT(_buf, _size) { _buf, _buf, _buf + _size } 

static inline char *strbuf_wpos(struct strbuf *buf)
{
    return buf->wptr;
}

static inline int strbuf_wrem(struct strbuf *buf)
{
    return buf->end - buf->wptr;
}

// bytes writen to buffer available to read
static inline int strbuf_avail(struct strbuf *buf)
{
    return buf->wptr - buf->data;
}

// resever len bytes in buf or error
static inline char *strbuf_wres(struct strbuf *buf, int len)
{
    int wrem = buf->end - buf->wptr;

    if (wrem < len) {
        // not enough space
        return  NULL;
    }

    char *wptr = buf->wptr;
    buf->wptr += len;

    return wptr;
}

static inline char *strbuf_strcat(struct strbuf *buf, const char *str, int len)
{
    char *wptr = strbuf_wres(buf, len);

    if (wptr) {
        memcpy(wptr, str, len);
    }

    return wptr;
}

static inline char *strbuf_strcat_sep(struct strbuf *buf, int ch, const char *str, int len)
{
    int add_ch = (buf->wptr > buf->data) ? 1 : 0;
    char *wptr = strbuf_wres(buf, len + add_ch);

    if (wptr) {
        if (add_ch) *wptr++ = ch;
        memcpy(wptr, str, len);
    }

    return wptr;
}

#endif
