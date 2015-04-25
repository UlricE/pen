#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "pen.h"
#include "diag.h"
#include "server.h"
#include "settings.h"

#ifdef HAVE_LINUX_IF_PACKET_H
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>

static char *mac2str(unsigned char *b)
{
	static char p[100];
	snprintf(p, sizeof p, "%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5]);
	return p;
}

static char *type2str(int type)
{
	switch (type) {
	case 0x0800: return "IPv4";
	case 0x0806: return "ARP";
	case 0x8100: return "802.1Q";
	case 0x86DD: return "IPv6";
	default: return "Unknown";
	}
}

static char *proto2str(int proto)
{
	switch (proto) {
	case 0x01: return "ICMP";
	case 0x06: return "TCP";
	case 0x17: return "UDP";
	default: return "Other";
	}
}

static void hexdump(uint8_t *b, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		printf("%02x ", b[i]);
		if ((i % 4) == 3) printf("\n");
	}
	if (i % 4) printf("\n");
}

#define MAXBUF 32000

static int port;

static void *frame, *payload;
static uint8_t *buf;
static uint8_t *mac_dst_p;
static uint8_t *mac_src_p;
static uint16_t *ethertype_p;

/* arp packet structure */
static uint16_t *arp_htype_p;
static uint16_t *arp_ptype_p;
static uint8_t *arp_hlen_p;
static uint8_t *arp_plen_p;
static uint16_t *arp_oper_p;
static uint8_t *arp_sha_p;        /* sender hardware address */
static struct in_addr *arp_spa_p; /* sender protocol address */
static uint8_t *arp_tha_p;        /* target hardware address */
static struct in_addr *arp_tpa_p; /* target protocol address */

/* ipv4 packet structure */
static uint8_t *ipv4_ihl_p;
static uint8_t *ipv4_protocol_p;
static struct in_addr *ipv4_src_p;
static struct in_addr *ipv4_dst_p;
static struct in_addr our_ip_addr;
static uint8_t our_hw_addr[6];

/* returns a raw socket or -1 for failure */
int dsr_init(char *dsr_if, char *listenport)
{
	buf = malloc(MAXBUF);
	frame = buf;
	mac_dst_p = frame;
	mac_src_p = frame+6;
	ethertype_p = frame+12;
	payload = frame+14;
	int n, ifindex, fd;
	struct sockaddr_ll sll;
 	struct ifreq ifr;
	char *dsr_ip, *dsr_port;

	/* arp packet structure */
	arp_htype_p = payload;
	arp_ptype_p = payload+2;
	arp_hlen_p = payload+4;
	arp_plen_p = payload+5;
	arp_oper_p = payload+6;
	arp_sha_p = payload+8;
	arp_spa_p = payload+14;
	arp_tha_p = payload+18;
	arp_tpa_p = payload+24;

	/* ipv4 packet structure */
	ipv4_ihl_p = payload;
	ipv4_protocol_p = payload+9;
	ipv4_src_p = payload+12;
	ipv4_dst_p = payload+16;

	dsr_ip = strtok(listenport, ":");
	dsr_port = strtok(NULL, ":");
	if (dsr_port) port = atoi(dsr_port);
	else port = 0;

	if (inet_aton(dsr_ip, &our_ip_addr) == 0) {
		debug("Address %s is not valid", dsr_ip);
		return -1;
	}

 	fd = socket_nb(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

	memset(&ifr, 0, sizeof ifr);

	/* display mac */
 	strncpy(ifr.ifr_name, dsr_if, IFNAMSIZ-1);
	n = ioctl(fd, SIOCGIFHWADDR, &ifr);
	if (n == -1) debug("ioctl: %s", strerror(errno));
	memcpy(our_hw_addr, ifr.ifr_hwaddr.sa_data, 6);
	DEBUG(2, "Our hw addr: %s\n", mac2str(our_hw_addr));

	/* display interface number */
	ioctl(fd, SIOCGIFINDEX, &ifr);
	ifindex = ifr.ifr_ifindex;
	DEBUG(2, "Index = %d", ifindex);

	/* bind to interface */
	memset(&sll, 0, sizeof sll);
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(fd, (struct sockaddr *)&sll, sizeof sll) == -1) {
		debug("bind: %s", strerror(errno));
	}

	return fd;
}

void send_arp_request(int fd, struct in_addr *a)
{
	int n;
	memset(mac_dst_p, 0xff, 6);
	memcpy(mac_src_p, our_hw_addr, 6);
	*ethertype_p = htons(0x0806);
	*arp_htype_p = htons(1);
	*arp_ptype_p = htons(0x0800);
	*arp_hlen_p = 6;
	*arp_plen_p = 4;
	*arp_oper_p = htons(1);
	memcpy(arp_sha_p, our_hw_addr, 6);
	memset(arp_spa_p, 0, 4);
	memset(arp_tha_p, 0, 6);
	memcpy(arp_tpa_p, a, 4);
	hexdump(buf, 42);
	n = sendto(fd, buf, 42, 0, NULL, 0);
	DEBUG(2, "Sent %d bytes arp request", n);
	if (n == -1) {
		debug("sendto: %s", strerror(errno));
	}
}

static void store_hwaddr(struct in_addr *ip, uint8_t *hw)
{
	int server;
	DEBUG(2, "Storing ARP reply");
	DEBUG(2, "Real address %s has hardware address %s",
		inet_ntoa(*ip), mac2str(hw));
	for (server = 0; server < nservers; server++) {
		struct sockaddr_storage *a = &servers[server].addr;
		if (a->ss_family == AF_INET) {
			struct sockaddr_in *si = (struct sockaddr_in *)a;
			if (memcmp(ip, &(si->sin_addr), 4) == 0) {
				memcpy(servers[server].hwaddr, hw, 6);
			}
		}
	}
}

static void arp_frame(int fd, int n)
{
	uint16_t arp_htype, arp_ptype, arp_oper;
	DEBUG(2, "ARP");
	arp_htype = ntohs(*arp_htype_p);
	arp_ptype = ntohs(*arp_ptype_p);
	arp_oper = ntohs(*arp_oper_p);
	DEBUG(2, "Hardware type: %d / %s", arp_htype,
		arp_htype == 1 ? "Ethernet" : "Other");
	DEBUG(2, "Protocol type: 0x%x / %s", arp_ptype,
		arp_ptype == 0x0800 ? "IPv4" : "Other");
	DEBUG(2, "Operation: %d / %s", arp_oper,
		arp_oper == 1 ? "Request" : "Reply");

	DEBUG(2, "Sender hardware address: %s", mac2str(arp_sha_p));
	DEBUG(2, "Sender protocol address: %s", inet_ntoa(*arp_spa_p));
	DEBUG(2, "Target hardware address: %s", mac2str(arp_tha_p));
	DEBUG(2, "Target protocol address: %s", inet_ntoa(*arp_tpa_p));
	if ((arp_htype == 1) &&
	    (arp_ptype == 0x0800) &&
	    (arp_oper == 1) &&
	    (memcmp(arp_tpa_p, &our_ip_addr, sizeof *arp_tpa_p) == 0)) {
		hexdump(buf, n);
		DEBUG(2, "We should reply to this.");
		memcpy(mac_dst_p, arp_sha_p, 6);
		memcpy(mac_src_p, our_hw_addr, 6);
		*arp_oper_p = htons(2);
		memcpy(arp_tha_p, arp_sha_p, 6);
		memcpy(arp_tpa_p, arp_sha_p, 4);
		memcpy(arp_sha_p, our_hw_addr, 6);
		memcpy(arp_spa_p, &our_ip_addr, 4);
		n = sendto(fd, buf, n, 0, NULL, 0);
		DEBUG(2, "Sent %d bytes", n);
		if (n == -1) {
			debug("sendto: %s", strerror(errno));
		}
	} else if ((arp_htype == 1) &&
		   (arp_ptype == 0x0800) &&
		   (arp_oper == 2)) {
		store_hwaddr(arp_spa_p, arp_sha_p);
	}
}

static int real_hw_known(int server)
{
	static uint8_t zero[6] = {0, 0, 0, 0, 0, 0};
	return (memcmp(servers[server].hwaddr, zero, 6) != 0);
}

#define HASH_INDEX_SIZE 256

static uint16_t hash_index[HASH_INDEX_SIZE];

static int rebuild_hash_index(void)
{
	int i, j;
	int t;			/* number of slots to fill */
	int s[SERVERS_MAX];	/* how many slots should each server occupy */
	int ls;			/* number of live, available servers */
	int tw;			/* total weights of all available servers */
	int w;

	DEBUG(3, "rebuild_hash_index()");
	/* first count how many servers we have */
	ls = 0;
	tw = 0;
	for (i = 0; i < nservers; i++) {
		if (server_is_unavailable(i)) {
			s[i] = -1;
		} else {
			if (servers[i].weight > 0) {
				s[i] = servers[i].weight;
			} else {
				s[i] = 1;
			}
			tw += s[i];
			ls++;
		}
	}
	DEBUG(3, "%d servers with total weight %d", ls, tw);
	if (tw == 0) {
		debug("No available servers, can't rebuild");
		return 0;	/* without setting ALG_HASH_VALID */
	}

	t = HASH_INDEX_SIZE;
	for (i = 0; i < nservers; i++) {
		if (s[i] == -1) continue;
		w = t*s[i]/tw;
		t -= w;
		tw -= s[i];
		s[i] = w;
		DEBUG(3, "Server %d gets %d slots; %d weight and %d slots remaining", i, w, tw, t);
	}

	t = HASH_INDEX_SIZE;
	j = 0;
	for (i = 0; t; i = (i+3) % HASH_INDEX_SIZE) {
		while (s[j] <= 0) j++;
		hash_index[i] = j;
		s[j]--;
		t--;
	}

#if 1
for (i = 0; i < HASH_INDEX_SIZE; i++) {
printf("%d ", hash_index[i]);
}
printf("\n");
#endif

	/* finally claim that the hash index is up to date */
	server_alg |= ALG_HASH_VALID;
	return 1;
}

static int hash(struct in_addr *a, uint16_t port)
{
	uint8_t *p = (uint8_t *)&a->s_addr;
	int h = p[0]^p[1]^p[2]^p[3];
	if (server_alg & ALG_ROUNDROBIN) {
		p = (uint8_t *)&port;
		h = h^p[0]^p[1];
	}
	return h;
}

static int select_server(struct in_addr *a, uint16_t port)
{
	int h = hash(a, port);
	int i;
	if ((server_alg & ALG_HASH_VALID) == 0) {
		if (!rebuild_hash_index()) return -1;	/* failure */
	}
	i = hash_index[h];
	DEBUG(3, "select_server returning server %d for hash %d", i, h);
	return i;
}

static void ipv4_frame(int fd, int n)
{
	uint8_t ipv4_protocol;
	uint8_t ipv4_ihl;
	void *tcp_segment;
	uint16_t *tcp_src_port_p, *tcp_dst_port_p;
	uint16_t tcp_src_port, tcp_dst_port;
	int server;

	DEBUG(2, "IPv4");
	ipv4_ihl = ((*ipv4_ihl_p) & 0xf)*4;
	ipv4_protocol = *ipv4_protocol_p;
	DEBUG(2, "IPv4 header size: %d bytes", ipv4_ihl);
	DEBUG(2, "Protocol: %d / %s", ipv4_protocol, proto2str(ipv4_protocol));
	DEBUG(2, "Sender IPv4 address: %s", inet_ntoa(*ipv4_src_p));
	DEBUG(2, "Destination IPv4 address: %s", inet_ntoa(*ipv4_dst_p));
	if ((ipv4_protocol == 6) &&
	    (*(uint32_t *)ipv4_dst_p == (uint32_t)our_ip_addr.s_addr)) {
		DEBUG(2, "We should forward this.");
		tcp_segment = payload+ipv4_ihl;
		tcp_src_port_p = tcp_segment;
		tcp_dst_port_p = tcp_segment+2;
		tcp_src_port = htons(*tcp_src_port_p);
		tcp_dst_port = htons(*tcp_dst_port_p);
		server = select_server(ipv4_src_p, tcp_src_port);
		if (server == -1) {
			debug("Dropping frame, nowhere to put it");
			return;
		}
		if (!real_hw_known(server)) {
			DEBUG(2, "Real hw addr unknown");
			return;
		}
		DEBUG(2, "Source port = %d, destination port = %d",
			tcp_src_port, tcp_dst_port);
		if (port == 0 || tcp_dst_port == port) {
			memcpy(mac_dst_p, servers[server].hwaddr, 6);
			n = sendto(fd, buf, n, 0, NULL, 0);
			DEBUG(2, "Sent %d bytes", n);
			if (n == -1) {
				debug("sendto: %s", strerror(errno));
			}
		}
	}
}

void dsr_arp(int fd)
{
	int server, since;
	static time_t last_arp = 0;
	struct sockaddr_in *si;

	DEBUG(2, "dsr_arp(%d)", fd);
	since = now-last_arp;
	DEBUG(2, "%d seconds since last update", since);
	if (since) {
		DEBUG(2, "Going through the server list");
		for (server = 0; server < nservers; server++) {
			DEBUG(2, "Checking server %d", server);
			if (unused_server_slot(server)) {
				DEBUG(2, "Server slot %d is unused", server);
				continue;
			}
			if (real_hw_known(server) && since < 60) {
				DEBUG(2, "Server %d hw address is known", server);
				continue;
			}
			si = (struct sockaddr_in *)&servers[server].addr;
			send_arp_request(fd, &si->sin_addr);
			last_arp = now;
		}
	}
}

void dsr_frame(int fd)
{
	int i, type, n;

	for (i = 0; i < multi_accept; i++) {
		n = recvfrom(fd, buf, MAXBUF, 0, NULL, NULL);
		DEBUG(2, "Received %d bytes", n);
		if (n == -1) return;

		DEBUG(2, "MAC destination: %s", mac2str(mac_dst_p));
		DEBUG(2, "MAC source: %s", mac2str(mac_src_p));
		type = ntohs(*ethertype_p);
		DEBUG(2, "EtherType: %s", type2str(type));
		switch (type) {
		case 0x0806:
			arp_frame(fd, n);
			break;
		case 0x0800:
			ipv4_frame(fd, n);
			break;
		default:
			DEBUG(2, "Other (%x)", type);
		}
	}
}

#else
int dsr_init(char *dsr_if, char *dsr_ip)
{
	error("Direct server return is not available");
	return -1;
}

void dsr_arp(int fd)
{
	error("Direct server return is not available");
}

void dsr_frame(int fd)
{
	error("Direct server return is not available");
}
#endif
