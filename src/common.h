/*
 * common.h by xenion -- 2008-05-05 -- v.1293c16fff21c9e111936bd906f13e1c
 *
 * Copyright (c) 2007-2008 Dallachiesa Michele <micheleDOTdallachiesaATposteDOTit>
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef COMMON_H
#define COMMON_H

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


/* const */

#define LINE_BUFFER_MAX 4096

#ifndef PATH_MAX
#define PATH_MAX        4096
#endif


/* macros */

// returns 1 if a > b, -1 if a < b, 0 if a == b
#define TIMEVAL_CMP(a, b) (            \
   a.tv_sec > b.tv_sec ? 1 :           \
   a.tv_sec < b.tv_sec ? -1 :          \
   a.tv_usec > b.tv_usec ? 1 :         \
   a.tv_usec < b.tv_usec ? -1 : 0 )

#define TIMEVAL_SUB(a, b, result)                          \
  do {                                                     \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;          \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;       \
    if ((result)->tv_usec < 0) {                           \
      --(result)->tv_sec;                                  \
      (result)->tv_usec += 1000000;                        \
    }                                                      \
  } while (0)

#define MAX(x,y) ( (x) > (y) ? (x) : (y))
#define MIN(x,y) ( (x) < (y) ? (x) : (y))

#define PERCENTAGE(x,y) ((y) == 0 ? 0 : (float)(x) * 100 / (y))

#define LOG(h,n,fmt, ...) do { \
   logthis(__FILE__, __FUNCTION__, __LINE__,0,h,n,fmt, ## __VA_ARGS__ );   \
    } while(0)

#define VLOG(h,n,fmt, ...) do { \
           logthis(__FILE__, __FUNCTION__, __LINE__,1,h,n,fmt, ## __VA_ARGS__ );   \
            } while(0)

#define FATAL(x, ...) do {                                      \
                   fatal(__FILE__, __FUNCTION__, __LINE__,x, ## __VA_ARGS__ );   \
                   } while(0)

#define SAFE_FREE(x) do { if (x) { free(x); x = NULL; }}while(0)
#define SAFE_CLOSE(x) do { if(x != -1) { close(x) ; x = -1;}}while(0)
#define SAFE_FCLOSE(x) do { if (x) { fclose(x); x = NULL; }}while(0)
#define SAFE_FPRINTF(x, ...) do { if(x) fprintf(x, ## __VA_ARGS__ ); } while(0)
#define SAFE_PDCLOSE(x) do { if (x) { pcap_dump_close(x); x = NULL; }}while(0)
#define SAFE_STRDUP(x) (*x ? strdup(x) : NULL)

#define SWITCH_VALUES(x,y,tmp) do { tmp=x; x=y; y=tmp; } while(0)

#define STATIC_STRLEN(x) (sizeof(x)-1) // (sizeof("ciao")-1) == 4

#define SIG_NAME(x) x == SIGURG  ? "SIGURG"  : \
                    x == SIGPIPE ? "SIGPIPE" : \
                    x == SIGQUIT ? "SIGQUIT" : \
                    x == SIGINT  ? "SIGINT"  : \
                    x == SIGTERM ? "SIGTERM" : \
                    x == SIGHUP  ? "SIGHUP"  : \
                    x == SIGSEGV ? "SIGSEGV" : \
                    x == SIGBUS  ? "SIGBUS"  : \
                    x == SIGUSR1 ? "SIGUSR1" : "UNKNOWN"


/* protos */

extern void fatal(char *file, const char *function, int line, const char *fmt, ...);
extern void logthis(char *file, const char *function, int line, int ifverbose,int h, int n, const char *fmt, ...);
extern void logmem(u_int8_t *p, u_int32_t len, u_int32_t cols, int format, char *lh);
extern char *str_char(unsigned char c);
extern void enable_verbose();
extern void disable_verbose();
extern void open_logfile(char *pathname);
extern void init_sighandlers();
extern void sig_lock();
extern void sig_unlock();
extern void close_logfile();
extern char *strtime(time_t t);
extern void drop_privs(char *user, char *group);
extern void daemonize();
extern int exists(char *pathname);
extern void enable_syslog();
extern void disable_syslog();
extern void enable_stdout();
extern void disable_stdout();
extern char *get_next_name(char *directory, char *prefix, char *suffix, int *i);
extern int isdirectory(char *pathname);
extern char *trim(char *str);
extern int parse_token(char *data, u_int32_t datalen, char *delims, char *found);
extern int parse_line(char *data, u_int32_t datalen);
extern int mystrnstr(char *str1, char *str2, int str1len);

#endif


/* eof */

