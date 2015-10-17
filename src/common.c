/*
 * common.c by xenion -- 2008-05-05 -- v.fdb23b830c7d63aa1208dfdad3ccf845
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


#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <dirent.h>
#include "common.h"


/* globals */

static int verbose_enabled = 0;
static FILE *f = NULL;
static int syslog_enabled = 0;
static int stdout_enabled = 0;
static char line_buffer[LINE_BUFFER_MAX] = {0, };


/* extern */

extern void cleanup();


/* protos */

void sigdie(int signo);


/*******************************************/


void enable_verbose()
{
  verbose_enabled = 1;
}


void disable_verbose()
{
  verbose_enabled = 0;
}


void enable_syslog()
{
  syslog_enabled = 1;
}


void disable_syslog()
{
  syslog_enabled = 0;
}


void enable_stdout()
{
  stdout_enabled = 1;
}


void disable_stdout()
{
  stdout_enabled = 0;
}


void open_logfile(char *pathname)
{
  if (f)
    SAFE_FCLOSE(f);

  if ((f =  fopen(pathname, "a")) == NULL)
    FATAL("fopen(): %s", strerror(errno));
}


void close_logfile()
{
  if (f != NULL && f != stdout && f != stderr)
    SAFE_FCLOSE(f);
}


void
logthis(char *file, const char *function, int line, int ifverbose,int h, int n, const char *fmt, ...)
{
  u_int32_t len;
  va_list ap;


  // The program must first execute the macro va_start within the body
  // of the function to initialize an object with context information.

  va_start(ap, fmt);

  if (ifverbose && verbose_enabled == 0)
    return;

  if (f == NULL) // stdout by default...
    f = stdout;
  if (f == stdout) // prevent double logging to stdout...
    disable_stdout();

  if (h)
    {
      line_buffer[0] = '\0';
      if (verbose_enabled)
        snprintf(line_buffer,LINE_BUFFER_MAX,"%s %s:%d:",strtime(time(NULL)),function, line);
    }

  len = strlen(line_buffer);

  vsnprintf(line_buffer+len,LINE_BUFFER_MAX-len,fmt, ap);

  len = strlen(line_buffer);

  if (len >= LINE_BUFFER_MAX-1)
    {
      // we reached the end-1... probably the string was truncated. we keep 1 byte for trailing '\n', inserted in if(n) ....
      line_buffer[0] = '\0';
      FATAL("line buffer full");
    }


  if (n)
    {

      line_buffer[len] = '\n';
      line_buffer[len+1] = 0;

      fprintf(f, "%s", line_buffer);
      fflush(f);

      if (syslog_enabled)
        syslog(LOG_DAEMON|LOG_INFO, line_buffer);

      if (stdout_enabled)
        printf("%s", line_buffer);

      line_buffer[0] = 0;
    }

  va_end(ap);
}


void
fatal(char *file, const char *function, int line, const char *fmt, ...)
{
  va_list         ap;


  // The program must first execute the macro va_start within the body
  // of the function to initialize an object with context information.

  va_start(ap, fmt);

  if (f == NULL)
    f = stdout;
  if (f == stdout)
    disable_stdout();
  disable_verbose();

  snprintf(line_buffer,LINE_BUFFER_MAX,"%s Fatal error at %s:%d:%s: ",strtime(time(NULL)),file, line, function);
  vsnprintf(line_buffer+strlen(line_buffer),LINE_BUFFER_MAX-strlen(line_buffer),fmt, ap);
  snprintf(line_buffer+strlen(line_buffer),LINE_BUFFER_MAX-strlen(line_buffer),"; exit forced.");

  if (strlen(line_buffer) >= LINE_BUFFER_MAX-1)
    {
      FATAL("line buffer full");
    }

  fprintf(f,"--\n%s\n--\n", line_buffer);

  if (syslog_enabled)
    syslog(LOG_DAEMON | LOG_ERR,"%s", line_buffer);

  if (stdout_enabled)
    printf("--\n%s\n--\n", line_buffer);

  va_end(ap);

  sig_unlock(); // if lock, unlock. else, nothing changes.
  sigdie(-1);
}


void
sigdie(int signo)
{
  static int loop = 0;


// if loop==1 happens, there's an infinite loop (and a bug somewhere ...). prevent it exiting. better than nothing...
  if (loop == 0)
    loop = 1;
  else
    exit(1);

// if signo == -1, it's a direct call from function fatal: less output
// messages looks better.

  if (signo != -1)
    {
      LOG(1,1,"--");
      LOG(1,1,"Caught %s signal (%d), cleaning up...", SIG_NAME(signo), signo);
      LOG(1,1,"--");
    }

  cleanup();

  LOG(1,1,"");
  // questa deve essere l'ultima cosa prima della exit.
  disable_syslog();
  close_logfile();
  disable_stdout();

  exit(signo == SIGTERM ? 0 : 1); // 0 == ok, 1 == err
}


void init_sighandlers()
{
  signal(SIGSEGV, sigdie);
  signal(SIGTERM, sigdie);
  signal(SIGINT, sigdie);
  signal(SIGUSR1, sigdie);
}


void sig_lock()
{
  signal(SIGTERM, SIG_IGN);
  signal(SIGINT, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
}


void sig_unlock()
{
  signal(SIGTERM, sigdie);
  signal(SIGINT, sigdie);
  signal(SIGUSR1, sigdie);
}


char *
strtime(time_t t)
{
  struct tm      *mytm;
  static char s[20];


  mytm = localtime(&t);
  strftime(s, 20, "%d/%m/%Y#%H:%M:%S", mytm);
  return s;
}


void drop_privs(char *user, char *group)
{
  struct passwd *p;
  struct group *g;
  int uid, gid;


  if (!user && !group)
    FATAL("(user == NULL && group == NULL)");

  if ((p = getpwnam(user)) == NULL)
    FATAL("(getpwnam(...) == NULL): user not found");

  uid = p->pw_uid;
  gid = p->pw_gid;

  if (group)
    {
      if ( (g = getgrnam(group)) == NULL)
        FATAL("(getgrnam(...) == NULL): group not found");
      gid = g->gr_gid;
    }


  if (setgid(gid) == -1)
    FATAL("setgid(...): %s",strerror(errno));

  if (setuid(uid) == -1)
    FATAL("setuid(...): %s",strerror(errno));

  if (setegid(gid) == -1)
    FATAL("setegid(...): %s",strerror(errno));

  if (seteuid(uid) == -1)
    FATAL("seteuid(...): %s",strerror(errno));
}


void daemonize()
{
  setsid();
  if (fork())
    exit(0);
}


int exists(char *pathname)
{
  struct stat st;
  int z;


  z = stat(pathname, &st);

  if (z == 0)
    return 1;

  if (errno == ENOENT)
    return 0;

  return -1; // maybe exists, maybe perm problems....
}


char *get_next_name(char *directory, char *prefix, char *suffix, int *i)
{
  int count;
  static char pathname[PATH_MAX];
  struct stat st;


  if (directory[0] != '\0' && // if directory specified...
      !isdirectory(directory))
    FATAL("'%s' is not a valid directory, check pathname and permissions", directory);

  for (count = 0;;)
    {
      snprintf(pathname, PATH_MAX, "%s/%s%d%s", directory, prefix, count, suffix);
      if (stat(pathname, &st) == -1)
        {
          if (errno == ENOENT)
            break;
          else
            {
              if (i)
                *i = -1;
              return NULL;
            }
        }
      count++;
    }

  if (i)
    *i = count;

  return pathname;
}


int isdirectory(char *pathname)
{
  struct stat st;

  if (stat(pathname, &st) != 0 || !S_ISDIR(st.st_mode))
    return 0;
  else return 1;
}


int mystrnstr(char *str1, char *str2, int str1len)
{
  int str2len, i;

  str2len = strlen(str2);

  if (str2len > str1len)
    return -1;

  for (i = 0; i <= str1len - str2len; i++)
    if (strncmp(str1+i, str2, str2len) == 0)
      return i;

  return -1;
}


char *trim(char *str)
{
  char *p;
  int i;

//  LOG(1,1,"input is '%s'", str);

  for (p = str;*p != 0 && (*p == ' ' || *p == '\t');p++);
  if (*p == 0)   // nothing to do!
    {
      //    LOG(1,1,"output is '%s'", p);
      return p;
    }

  for (i = strlen(p);i >= 0 && (p[i] == 0 || p[i] == '\t' || p[i] == ' ');i--);
  if (i >= 0 && p[i] != 0)
    p[i+1] = 0;

//LOG(1,1,"output is '%s'", p);


  return p;
}


int parse_token(char *data, u_int32_t datalen, char *delims, char *found)
{
  int i,j,l;

//LOG(1,1,"parse_token:");
//fwrite(data,1, datalen,stdout);
//LOG(1,1,"-------------");

  l = strlen(delims);
  for (i = 0; i < datalen; i++)
    {
      for (j = 0; j < l; j++)
        {
          if (data[i] == delims[j])
            break;
        }
      if (data[i] == delims[j])
        break; // propagate...
    }

  if (i == datalen)
    return -1;

  if (found)
    *found = data[i];

  data[i] = 0;

  return i+1;
}


int parse_line(char *data, u_int32_t datalen)
{
  int i;


  if (datalen <= 0)
    return -1;

  if ((i = parse_token(data, datalen, "\n",NULL)) == -1)
    return -1;

  if (i > 1 && data[i -2] == '\r')
    data[i-2] = 0;

  return i;
}


char *str_char(unsigned char c)
{
  static char s[8];


  if (c >= 32 && 126)
    {
      sprintf(s,"'%c' ", c);
      return s;
    }

  switch (c)
    {
    case '\0':
      return "'\\0'";
    case '\r':
      return "'\\r'";
    case '\n' :
      return "'\\n'";
    default:
      sprintf(s,"?%.3d", c);
      return s;
    }

}


void
logmem(u_int8_t *p, u_int32_t len, u_int32_t cols, int format, char *lh)
{
  u_int32_t off,line,col;


  if (format == 1 && cols != 1)
    FATAL("with fmt == 1 you must use cols == 1");

  if (!lh)
    lh = "";

  LOG(1,0,"%s+ Dumping memory from %p for %d bytes, cols: %d, fmt: ",lh, p,len, cols);

  switch (format)
    {
    case 1:
      LOG(0,1,"hex bin dec chr");
      break;
    case 2:
      LOG(0,1,"hex");
      break;
    default:
      FATAL("undefined format: %d", format);
    }

  for (off=0,col=0,line=0;off<len;off++)
    {
      if (col == 0)
        {
          if (line > 0)
            LOG(0,1,"");
          LOG(1,0,"%s| %p+%-8d",lh, p,off);
        }

      switch (format)
        {
        case 1:
          LOG(0,0,"0x%.2x %d%d%d%d%d%d%d%d %.3d %s",p[off],p[off] & 0x80 ? 1 : 0,p[off] & 0x40 ? 1 : 0,p[off] & 0x20 ? 1 : 0,p[off] & 0x10 ? 1 : 0,p[off] & 0x08 ? 1 : 0,p[off] & 0x04 ? 1 : 0,p[off] & 0x02 ? 1 : 0,p[off] & 0x01 ? 1 : 0, p[off], str_char(p[off]));
          break;
        case 2:
          LOG(0,0," %.2x",p[off]);
          break;
        default:
          FATAL("undefined format: %d", format);
        }

      if (++col >= cols)
        {
          col = 0;
          line++;
        }
    }

  LOG(0,1,"");
  LOG(1,1,"%s+ End", lh);
}


/* EOF*/

