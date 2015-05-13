#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#ifndef WINDOWS
#include <syslog.h>
#else
#include "windows.h"
#endif
#include "settings.h"

int debuglevel;

#ifdef WINDOWS
static FILE *syslogfp;

static void openlog(const char *ident, int option, int facility)
{
	syslogfp = fopen("syslog.txt", "a");
}

static void syslog(int priority, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	if (syslogfp) {
		vfprintf(syslogfp, format, ap);
	}
	va_end(ap);
}

static void closelog(void)
{
	fclose(syslogfp);
}
#endif

void debug(char *fmt, ...)
{
	time_t now;
	struct tm *nowtm;
	char nowstr[80];
	char b[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	now=time(NULL);
	nowtm = localtime(&now);
	strftime(nowstr, sizeof(nowstr), "%Y-%m-%d %H:%M:%S", nowtm);
	if (foreground) {
		fprintf(stderr, "%s: %s\n", nowstr, b);
	} else {
		openlog("pen", LOG_CONS, LOG_USER);
		syslog(LOG_DEBUG, "%s\n", b);
		closelog();
	}
	va_end(ap);
}

void error(char *fmt, ...)
{
	char b[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(b, sizeof b, fmt, ap);
	fprintf(stderr, "%s\n", b);
	if (!foreground) {
		openlog("pen", LOG_CONS, LOG_USER);
		syslog(LOG_ERR, "%s\n", b);
		closelog();
	}
	va_end(ap);
	if (abort_on_error) abort();
	else exit(EXIT_FAILURE);
}

