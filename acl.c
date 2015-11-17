#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef WINDOWS
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif
#ifdef HAVE_LIBGEOIP
#include <GeoIP.h>
GeoIP *geoip4, *geoip6;
#endif

#include "acl.h"
#include "diag.h"
#include "memory.h"
#include "netconv.h"
#include "windows.h"

#define ACE_IPV4 (1)
#define ACE_IPV6 (2)
#define ACE_GEO (3)

static int nacls[ACLS_MAX];
static acl *acls[ACLS_MAX];
static unsigned char mask_ipv6[129][16];

static void init_mask(void)
{
	unsigned char m6[16];
	int i, j;

	memset(m6, 0, sizeof m6);
	for (i = 0; i < 129; i++) {
		for (j = 15; j >= 0; j--) {
			mask_ipv6[i][j] = m6[j];
			m6[j] >>= 1;
			if (j > 0) {
				m6[j] |= (m6[j-1] << 7);
			} else {
				m6[j] |= (1 << 7);
			}
		}
	}
}

/* allocate ace and fill in the generics */
static int add_acl(int a, unsigned char permit)
{
	int i;
	if (a < 0 || a >= ACLS_MAX) {
		debug("add_acl: %d outside (0,%d)", a, ACLS_MAX);
		return -1;
	}
	i = nacls[a]++;
	acls[a] = pen_realloc(acls[a], nacls[a]*sizeof(acl));
	acls[a][i].permit = permit;
	return i;
}

void add_acl_ipv4(int a, unsigned int ip, unsigned int mask, unsigned char permit)
{
	int i = add_acl(a, permit);

	if (i == -1) return;

	DEBUG(2, "add_acl_ipv4(%d, %x, %x, %d)", a, ip, mask, permit);
	acls[a][i].class = ACE_IPV4;
	acls[a][i].ace.ipv4.ip = ip;
	acls[a][i].ace.ipv4.mask = mask;
}

void add_acl_ipv6(int a, unsigned char *ipaddr, unsigned char len, unsigned char permit)
{
	int i = add_acl(a, permit);

	if (i == -1) return;

	DEBUG(2, "add_acl_ipv6(%d, %x, %d, %d)\n" \
		"%x:%x:%x:%x:%x:%x:%x:%x/%d", \
		a, ipaddr, len, permit, \
		256*ipaddr[0]+ipaddr[1], 256*ipaddr[2]+ipaddr[3], 256*ipaddr[4]+ipaddr[5], 256*ipaddr[6]+ipaddr[7], \
		256*ipaddr[8]+ipaddr[9], 256*ipaddr[10]+ipaddr[11], 256*ipaddr[12]+ipaddr[13], 256*ipaddr[14]+ipaddr[15],  len);
	acls[a][i].class = ACE_IPV6;
	memcpy(acls[a][i].ace.ipv6.ip.s6_addr, ipaddr, 16);
	acls[a][i].ace.ipv6.len = len;
}

void add_acl_geo(int a, char *country, unsigned char permit)
{
	int i = add_acl(a, permit);

	if (i == -1) return;

	DEBUG(2, "add_acl_geo(%d, %s, %d", a, country, permit);
	acls[a][i].class = ACE_GEO;
	strncpy(acls[a][i].ace.geo.country, country, 2);
}

void del_acl(int a)
{
	DEBUG(2, "del_acl(%d)", a);
	if (a < 0 || a >= ACLS_MAX) {
		debug("del_acl: %d outside (0,%d)", a, ACLS_MAX);
		return;
	}
	free(acls[a]);
	acls[a] = NULL;
	nacls[a] = 0;
}

#ifndef WINDOWS
static int match_acl_unix(int a, struct sockaddr_un *cli_addr)
{
	DEBUG(2, "Unix acl:s not implemented");
	return 1;
}
#endif

static int match_acl_ipv4(int a, struct sockaddr_in *cli_addr)
{
	unsigned int client = cli_addr->sin_addr.s_addr;
	int i;
	int permit = 0;
	acl *ap = acls[a];
#ifdef HAVE_LIBGEOIP
	const char *country = NULL;
	int geo_done = 0;
#endif
	DEBUG(2, "match_acl_ipv4(%d, %u)", a, client);
	for (i = 0; i < nacls[a]; i++) {
		permit = ap[i].permit;
		switch (ap[i].class) {
		case ACE_IPV4:
			if ((client & ap[i].ace.ipv4.mask) == ap[i].ace.ipv4.ip) {
				return permit;
			}
			break;
		case ACE_GEO:
#ifdef HAVE_LIBGEOIP
			if (geoip4 == NULL) break;
			if (!geo_done) {
				country = GeoIP_country_code_by_addr(geoip4,
						pen_ntoa((struct sockaddr_storage *)cli_addr));
				DEBUG(2, "Country = %s", country?country:"unknown");
				geo_done = 1;
			}
			if (country && !strncmp(country,
						ap[i].ace.geo.country, 2)) {
				return permit;
			}
#else
			debug("ACE_GEO: Not implemented");
#endif
			break;
		default:
			/* ignore other ACE classes (ipv6 et al) */
			break;
		}
	}
	return !permit;
}

/* The most straightforward way to get at the bytes of an ipv6 address
   is to take the pointer to the in6_addr and cast it to a pointer to
   unsigned char.
*/
static int match_acl_ipv6(int a, struct sockaddr_in6 *cli_addr)
{
	unsigned char *client = (unsigned char *)&(cli_addr->sin6_addr);
	unsigned char *ip;
	unsigned char *mask;
	int len;
	int i, j;
	int permit = 0;
	acl *ap = acls[a];
#ifdef HAVE_LIBGEOIP
	const char *country = NULL;
	int geo_done = 0;
#endif

	DEBUG(2, "match_acl_ipv6(%d, %u)", a, client);
	for (i = 0; i < nacls[a]; i++) {
		permit = ap[i].permit;
		switch (ap[i].class) {
		case ACE_IPV6:
			len = ap[i].ace.ipv6.len;
			ip = (unsigned char *)&(ap[i].ace.ipv6.ip);
			mask = mask_ipv6[len];

			DEBUG(2, "Matching %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x against %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x / %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", \
				client[0], client[1], client[2], client[3], \
				client[4], client[5], client[6], client[7], \
				client[8], client[9], client[10], client[11], \
				client[12], client[13], client[14], client[15], \
				ip[0], ip[1], ip[2], ip[3], \
				ip[4], ip[5], ip[6], ip[7], \
				ip[8], ip[9], ip[10], ip[11], \
				ip[12], ip[13], ip[14], ip[15], \
				mask[0], mask[1], mask[2], mask[3], \
				mask[4], mask[5], mask[6], mask[7], \
				mask[8], mask[9], mask[10], mask[11], \
				mask[12], mask[13], mask[14], mask[15]);

			for (j = 0; j < 16; j++) {
				if ((client[j] & mask[j]) != ip[j]) break;
			}
			if (j == 16) return permit;
			break;
		case ACE_GEO:
#ifdef HAVE_LIBGEOIP
			if (geoip6 == NULL) break;
			if (!geo_done) {
				country = GeoIP_country_code_by_addr_v6(geoip6,
						pen_ntoa((struct sockaddr_storage *)cli_addr));
				DEBUG(2, "Country = %s", country?country:"unknown");
				geo_done = 1;
			}
			if (country && !strncmp(country,
						ap[i].ace.geo.country, 2)) {
				return permit;
			}
#else
			debug("ACE_GEO: Not implemented");
#endif
			break;
		default:
			/* ignore other ACE classes (ipv4 et al) */
			break;
		}
	}
	return !permit;
}

/* returns nonzero if the acl is matched, zero otherwise */
int match_acl(int a, struct sockaddr_storage *cli_addr)
{
	if (a < 0 || a > ACLS_MAX) return 0;	/* acl out of bounds */
	switch (cli_addr->ss_family) {
#ifndef WINDOWS
	case AF_UNIX:
		return match_acl_unix(a, (struct sockaddr_un *)cli_addr);
#endif
	case AF_INET:
		return match_acl_ipv4(a, (struct sockaddr_in *)cli_addr);
	case AF_INET6:
		return match_acl_ipv6(a, (struct sockaddr_in6 *)cli_addr);
	default:
		debug("match_acl: unknown address family %d", cli_addr->ss_family);
	}
	return 0;
}

void save_acls(FILE *fp)
{
	int i, j;
	struct in_addr ip;
	char ip_str[INET6_ADDRSTRLEN];
	for (i = 0; i < ACLS_MAX; i++) {
		fprintf(fp, "no acl %d\n", i);
		for (j = 0; j < nacls[i]; j++) {
			fprintf(fp, "acl %d %s ", i,
				acls[i][j].permit?"permit":"deny");
			switch (acls[i][j].class) {
			case ACE_IPV4:
				memcpy(&ip, &acls[i][j].ace.ipv4.ip, 4);
				fprintf(fp, "%s ", inet_ntoa(ip));
				memcpy(&ip, &acls[i][j].ace.ipv4.mask, 4);
				fprintf(fp, "%s\n", inet_ntoa(ip));
				break;
			case ACE_IPV6:
				fprintf(fp, "%s/%d\n",
					inet_ntop(AF_INET6,
						&acls[i][j].ace.ipv6.ip,
						ip_str, sizeof ip_str),
					acls[i][j].ace.ipv6.len);
				break;
			case ACE_GEO:
				fprintf(fp, "country %c%c\n",
					acls[i][j].ace.geo.country[0],
					acls[i][j].ace.geo.country[1]);
				break;
			default:
				debug("Unknown ACE class %d (this is probably a bug)",
					acls[i][j].class);
			}
		}
	}
}

void acl_init(void)
{
	init_mask();
	#ifdef HAVE_LIBGEOIP
	geoip4 = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_MEMORY_CACHE);
	if (geoip4 == NULL) debug("Could not initialize GeoIP for IPv4");
	geoip6 = GeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_MEMORY_CACHE);
	if (geoip6 == NULL) debug("Could not initialize GeoIP for IPv6");
#endif
}
