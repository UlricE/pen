/*
   mergelogs.c

   Copyright (C) 2001-2015  Ulric Eriksson <ulric@siag.nu>
 
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

#define KEEP_MAX 100	/* how much to keep from the URI */

typedef struct {
	char *a;	/* server name */
	char *fn;	/* log file name */
	FILE *fp;	/* file pointer, or NULL if eof */
	time_t t;	/* time stamp from last line */
	char cli[1024];	/* client address */
	char tim[1024];	/* time string */
	char uri[1024];	/* uri */
	char b1[1024], b2[1024], b3[1024];	/* misc text */
} server;

static server *servers;
static int nservers;
static int debuglevel = 0;

static char *pfile;
static int jitter = 600;	/* 10 minutes */
static FILE *pfp;
static int tz = 0;
static int cache_penlog = 1;

static char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static void debug(char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fprintf(stderr, "\n");
}

static void error(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void *pen_malloc(size_t n)
{
	char *q = malloc(n);
	if (!q) error("Can't allocate %ld bytes", (long)n);
	return q;
}

static void *pen_calloc(size_t n, size_t s)
{
	char *q = calloc(n, s);
	if (!q) error("Can't allocate %ld bytes", (long)n*s);
	return q;
}

static void *pen_realloc(void *p, size_t n)
{
	char *q = realloc(p, n);
	if (!q) error("Can't allocate %ld bytes", (long)n);
	return q;
}

static char *pen_strdup(char *p)
{
	char *q = pen_malloc(strlen(p)+1);
	return strcpy(q, p);
}

static void usage(void)
{
	printf("Usage: mergelogs -p penlog [-j jitter] \\\n"
	       "        server1:logfile1 [server2:logfile2 ...]\n\n"
	       "  -c                Do not use penlog cache\n"
	       "  -d                Debugging (repeat for more)\n"
	       "  -p penlog         Log file from pen\n"
	       "  -j jitter         Jitter in seconds [2]\n"
	       "  -r filename       Where to put rejects\n"
	       "  -t seconds        Timezone\n"
	       "  server:logfile    Web server address and name of logfile\n");
	exit(0);
}

static int options(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "p:a:j:t:cd")) != -1) {
		switch (c) {
		case 'p':
			pfile = optarg;
			break;
		case 'j':
			jitter = atoi(optarg);
			break;
		case 't':
			tz = atoi(optarg);
			break;
		case 'c':
			cache_penlog = 0;
			break;
		case 'd':
			debuglevel++;
			break;
		default:
			usage();
		}
	}
	return optind;
}

static int mon2num(char *p)
{
	int i;

	for (i = 0; i < 12; i++)
		if (!strcmp(p, months[i])) return i;
	return -1;
}

static char *num2mon(int m)
{
	if (m < 0 || m > 11) return "no such month";
	return months[m];
}

static void thenp(char *b, time_t t)
{
	struct tm *tms = localtime(&t);
	sprintf(b, "%02d/%s/%04d:%02d:%02d:%02d +0000",
		tms->tm_mday, num2mon(tms->tm_mon), tms->tm_year+1900,
		tms->tm_hour, tms->tm_min, tms->tm_sec);
}

/*
Time format: 09/Jan/2002:00:27:15 +0100
*/
static time_t whenp(char *p, struct tm *tms)
{
	char dd[100], mm[100], yy[100];
	char hh[100], mi[100], ss[100], tz[100];
	time_t t;

	tz[0] = '\0';
	sscanf(p, "%[^/]/%[^/]/%[^:]:%[^:]:%[^:]:%s %s",
		dd, mm, yy, hh, mi, ss, tz);
	tms->tm_sec = atoi(ss);
	tms->tm_min = atoi(mi);
	tms->tm_hour = atoi(hh);
	tms->tm_mday = atoi(dd);
	tms->tm_mon = mon2num(mm);
	tms->tm_year = atoi(yy)-1900;
	t = mktime(tms);
	if (t != -1 && strlen(tz) == 5) {
		int d = 60*atoi(tz+3);
		tz[3] = '\0';
		d += 3600*atoi(tz+1);
		if (tz[0] == '+') t -= d;
		else t += d;
	}
	return t;
}

static void read_server_line(int s)
{
	char b[1024];
	struct tm tms;
	int n;

	do {
		if (fgets(b, sizeof b, servers[s].fp) == NULL) {
			fclose(servers[s].fp);
			servers[s].fp = NULL;
			return;
		}
	
		n = sscanf(b, "%[^ ] %[^[][%[^]]]%[^\"]\"%[^\"]\"%[^\n]",
			servers[s].cli, servers[s].b1, servers[s].tim,
			servers[s].b2, servers[s].uri, servers[s].b3);
		if (n == 6) {
			servers[s].t = whenp(servers[s].tim, &tms);
		} else if (debuglevel) {
			debug("Read %d fields", n);
		}
	} while (n != 6);
}

static int oldest_server(void)
{
	int i, n = -1;
	time_t t = -1;
	for (i = 0; i < nservers; i++) {
		if (servers[i].fp) {
			if (t == -1 || servers[i].t < t) {
				n = i;
				t = servers[i].t;
			}
		}
	}
	return n;
}

typedef struct {
	char *cli;	/* client address */
	int ser;	/* server index (in servers array) */
	time_t t;	/* time stamp */
	char *uri;	/* uri */
} pencache;

static pencache *pc;
static int npc;

static int server2num(char *s)
{
	int i;
	for (i = 0; i < nservers; i++) {
		if (!strcmp(servers[i].a, s)) return i;
	}
	return -1;
}

/* cache relevant penlog lines to speed up the search */
static void best_client1(char *p, char *s, long t, char *u)
{
	char b[1024], from[1024], to[1024], uri[1024];
	long when, td, ntd;
	int i, j;
	int ser = server2num(s);

	/* first remove all entries that are older than (t-jitter) */
	for (i = 0; i < npc; i++) {
		if (pc[i].t >= (t-jitter)) break;
	}
	if (i) {
		if (debuglevel) debug("uncache %d lines\n", i);
		for (j = 0; j < i; j++) {
			if (debuglevel >= 2) {
				debug("uncache '%s %ld %d %s'",
					pc[j].cli, pc[j].t,
					pc[j].ser, pc[j].uri);
			}
			free(pc[j].cli);
			free(pc[j].uri);
		}
		while (j < npc) {
			pc[j-i] = pc[j];
			j++;
		}
		npc -= i;
	}

	/* then add entries until eof or newer than (t+jitter) */
	for (;;) {
		if (npc > 0 && pc[npc-1].t > (t+jitter)) break;
		if (feof(pfp)) break;
		if (fgets(b, sizeof b, pfp) == NULL) break;
		pc = pen_realloc(pc, (npc+1)*sizeof *pc);
		if (debuglevel) debug("pc = %p, b = '%s'", pc, b);
		if (sscanf(b, "%s %ld %s %[^\n]", from, &when, to, uri) != 4) {
			continue;
		}
		pc[npc].cli = pen_strdup(from);
		pc[npc].ser = server2num(to);
		pc[npc].t = when-tz;
		pc[npc].uri = pen_strdup(uri);
		if (debuglevel >= 2) {
			debug("cache '%s %ld %d %s'",
				pc[npc].cli, pc[npc].t,
				pc[npc].ser, pc[npc].uri);
		}
		npc++;
	}

	/* now search the cache for a best match */
	snprintf(p, 1024, "%s", s);
	td = LONG_MAX;

	for (i = 0; i < npc; i++) {
		if (ser != pc[i].ser) continue;
		if (strcmp(u, pc[i].uri)) continue;
		ntd = labs(t-pc[i].t);
		if (ntd < td) {
			td = ntd;
			snprintf(p, 1024, "%s", pc[i].cli);
		}
	}
}

/* same again, this time without the cache */
static void best_client0(char *p, char *s, long t, char *u)
{
	char b[1024], from[1024], to[1024], uri[1024];
	long when, td, ntd;
	rewind(pfp);
	snprintf(p, 1024, "%s", s);	/* default is client = server */
	td = LONG_MAX;
	while (fgets(b, sizeof b, pfp)) {
		if (sscanf(b, "%s %ld %s %[^\n]", from, &when, to, uri) != 4) {
			continue;
		}
		if (strcmp(s, to)) continue;
		if (strcmp(u, uri)) continue;
		when -= tz;
		ntd = labs(t-when);
		if (ntd < td) {
			td = ntd;
			snprintf(p, 1024, "%s", from);
		}
	}
	if (debuglevel && td > 600) {
		debug("Warning: time difference %ld", td);
	}
}

static void best_client(char *p, char *s, long t, char *u)
{
	if (cache_penlog) best_client1(p, s, t, u);
	else best_client0(p, s, t, u);
}

int main(int argc, char **argv)
{
	int i, n, s;

	n = options(argc, argv);
	argc -= n;
	argv += n;
	if (argc < 1) {
		usage();
	}
	if (pfile == NULL) error("pfile null");
	pfp = fopen(pfile, "r");
	if (pfp == NULL) error("pfp null");

	s = 0;
	servers = pen_calloc(argc, sizeof *servers);
	for (i = 0; i < argc; i++) {
		servers[s].a = pen_strdup(argv[i]);
		servers[s].fn = strchr(servers[s].a, ':');
		if (servers[s].fn == NULL)
			error("Bogus server '%s'\n", argv[i]);
		*servers[s].fn++ = '\0';
		servers[s].fp = fopen(servers[s].fn, "r");
		if (servers[s].fp == NULL)
			error("Can't open logfile '%s'\n", servers[s].fn);
		read_server_line(s);
		nservers++;
		s++;
	}

/*
Example log lines:
10.0.18.6 - - [09/Jan/2002:00:28:50 +0100] "GET /robots.txt HTTP/1.0" 404 268
10.0.18.6 - - [09/Jan/2002:00:28:50 +0100] "GET /news.html HTTP/1.0" 200 4017

That is: client, whatever, whatever, [timestamp], "URI", code, size.
*/

	while ((s = oldest_server()) != -1) {
		char cli[1024], tim[1024];

		thenp(tim, servers[s].t);
		best_client(cli, servers[s].a, servers[s].t, servers[s].uri);
		if (debuglevel >= 2) {
			debug("\tclient = '%s' => '%s'",
				servers[s].cli, cli);
			debug("\ttime = '%s' => %d => '%s'",
				servers[s].cli, cli, servers[s].tim,
				(int)servers[s].t, tim);
			debug("\turi = '%s'",
				servers[s].uri);
		}
		printf("%s %s[%s]%s\"%s\"%s\n",
			cli, servers[s].b1, tim,
			servers[s].b2, servers[s].uri, servers[s].b3);
		read_server_line(s);
	}
	fclose(pfp);
	return 0;
}
