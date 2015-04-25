#include <stdlib.h>
#include <string.h>
#include "diag.h"

void *pen_malloc(size_t n)
{
	void *q = malloc(n);
	if (!q) error("Can't malloc %ld bytes", (long)n);
	return q;
}

void *pen_calloc(size_t n, size_t s)
{
	void *q = calloc(n, s);
	if (!q) error("Can't calloc %ld bytes", (long)n*s);
	return q;
}

void *pen_realloc(void *p, size_t n)
{
	void *q = realloc(p, n);
	if (!q) error("Can't realloc %ld bytes", (long)n);
	return q;
}

char *pen_strdup(const char *p)
{
	size_t len = strlen(p);
	char *b = pen_malloc(len+1);
	memcpy(b, p, len);
	b[len] = '\0';
	return b;
}

