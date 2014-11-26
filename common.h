/*
 * common.h
 * Common header file
 *
 * @author : Himanshu Mehra
 * @email  : hmehra@usc.edu
 * @project: ISI Project
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <sys/time.h>
#include <time.h>

/* Handy defines */
#define TRUE    1
#define FALSE   0

/* Constants */
#define MAX_ROUTERS             16
#define MAX_NAME_LEN            64
#define DEFAULT_TTL             64
#define MAX_BUF_LEN             256
#define ENDHOST_NOTIF_PORT      64321

#define max(a,b)   ((a) > (b) ? (a) : (b))
#define RANDOM()   ((double)rand() / (double)(RAND_MAX))


#ifdef DEBUG
#define DEBUG_LOG(__fmt...)                         \
do {                                                \
    char  str[MAX_BUF_LEN] = {0};                   \
    printf("[%s]  ", __timestr(str, sizeof(str)));  \
    printf(__fmt);                                  \
} while (0);
#else
#define DEBUG_LOG(__fmt...)
#endif


#ifdef DEBUG
#define DEBUG_VAR(a, b)  a b
#else
#define DEBUG_VAR(a, b)
#endif


#define PUT_UINT32(buf, val)                    \
do {                                            \
     (*((buf) + 0)) = (val & 0xFF000000) >> 24; \
     (*((buf) + 1)) = (val & 0x00FF0000) >> 16; \
     (*((buf) + 2)) = (val & 0x0000FF00) >> 8;  \
     (*((buf) + 3)) = (val & 0x000000FF);       \
} while (0)

#define GET_UINT32(buf)                         \
    ((*((uint8_t *) buf + 0) << 24)  |          \
     (*((uint8_t *) buf + 1) << 16)  |          \
     (*((uint8_t *) buf + 2) << 8)   |          \
     (*((uint8_t *) buf + 3)))


static inline char *
__timestr (char *buf, uint16_t buflen)
{
    struct timeval   tv;
    struct tm       *tm;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    assert(tm != NULL);

    strftime(buf, MAX_BUF_LEN,
             "%Y-%m-%d %H:%M:%S", tm);
    return buf;
}

static inline double
__time (void)
{
    struct timeval   tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + (double)(tv.tv_usec/1000000);
}


#endif  /* #ifndef __COMMON_H__ */
