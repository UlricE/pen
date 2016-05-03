#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "acl.h"
#include "pen.h"
#include "diag.h"
#include "memory.h"
#include "server.h"
#include "settings.h"

int tarpit_acl = -1;

#if defined(HAVE_LINUX_IF_PACKET_H) || defined(HAVE_NET_NETMAP_USER_H)
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
		if ((i % 8) == 7) printf("\n");
	}
	if (i % 8) printf("\n");
}

#define MAXBUF 32000

#define MAC_DST(f) (uint8_t *)(f)
#define MAC_SRC(f) (uint8_t *)(f+6)
#define ETHERTYPE(f) (uint16_t *)(f+12)
#define PAYLOAD(f) (f+14)
#define ARP_HTYPE(f) (uint16_t *)(PAYLOAD(f))
#define ARP_PTYPE(f) (uint16_t *)(PAYLOAD(f)+2)
#define ARP_HLEN(f) (uint8_t *)(PAYLOAD(f)+4)
#define ARP_PLEN(f) (uint8_t *)(PAYLOAD(f)+5)
#define ARP_OPER(f) (uint16_t *)(PAYLOAD(f)+6)
#define ARP_SHA(f) (uint8_t *)(PAYLOAD(f)+8)
#define ARP_SPA(f) (struct in_addr *)(PAYLOAD(f)+14)
#define ARP_THA(f) (uint8_t *)(PAYLOAD(f)+18)
#define ARP_TPA(f) (struct in_addr *)(PAYLOAD(f)+24)
#define IPV4_IHL(f) (uint8_t *)(PAYLOAD(f))
#define IPV4_PROTOCOL(f) (uint8_t *)(PAYLOAD(f)+9)
#define IPV4_SRC(f) (struct in_addr *)(PAYLOAD(f)+12)
#define IPV4_DST(f) (struct in_addr *)(PAYLOAD(f)+16)

#define TCP_SEGMENT(f, i) (PAYLOAD(f)+i)
#define TCP_SRC_PORT(f, i) (uint16_t *)(TCP_SEGMENT(f, i))
#define TCP_DST_PORT(f, i) (uint16_t *)(TCP_SEGMENT(f, i)+2)
#define TCP_SEQ_NR(f, i) (uint32_t *)(TCP_SEGMENT(f, i)+4)
#define TCP_ACK_NR(f, i) (uint32_t *)(TCP_SEGMENT(f, i)+8)
#define TCP_FLAGS(f, i) (uint16_t *)(TCP_SEGMENT(f, i)+12)
#define TCP_WINDOW(f, i) (uint16_t *)(TCP_SEGMENT(f, i)+14)
#define TCP_CHECKSUM(f, i) (uint16_t *)(TCP_SEGMENT(f, i)+16)
#define TCP_URGENT(f, i) (uint16_t *)(TCP_SEGMENT(f, i)+18)
#define TCP_OPTIONS(f, i) (uint8_t *)(TCP_SEGMENT(f, i)+20)

#define UDP_SEGMENT(f, i) (PAYLOAD(f)+i)
#define UDP_SRC_PORT(f, i) (uint16_t *)(UDP_SEGMENT(f, i))
#define UDP_DST_PORT(f, i) (uint16_t *)(UDP_SEGMENT(f, i)+2)

struct l2_frame {
	uint8_t mac_dst[6];
	uint8_t mac_src[6];
	uint16_t ethertype;
	uint8_t payload[1500];
};

struct ip_header {
	uint8_t ver_ihl, dscp_ecn;
	uint16_t length;
	uint16_t id, flags_offset;
	uint8_t ttl, proto;
	uint16_t header_cksum;
	uint32_t src, dst;
	uint32_t options;
};

struct pseudo_header {
	uint32_t src, dst;
	uint8_t zero, proto;
	uint16_t length;
};

struct tcp_header {
	uint16_t sport, dport;
	uint32_t seqnr;
	uint32_t acknr;
	uint16_t flags, winsize;
	uint16_t cksum, urgent;
	uint8_t options[40];
};

struct udp_header {
	uint16_t sport, dport;
	uint16_t length, cksum;
};

static int port;

static uint8_t *buf;
static struct in_addr our_ip_addr;

static uint8_t our_hw_addr[6];

/* OS specific features */
#ifdef HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
#include <netinet/ether.h>

static int dsr_init_os(char *dsr_if)
{
	int fd, n, ifindex;
 	struct ifreq ifr;
	struct sockaddr_ll sll;
 	fd = socket_nb(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

	buf = pen_malloc(MAXBUF);
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
		error("bind: %s", strerror(errno));
	}
	return fd;
}

static int send_packet(int fd, const void *b, int len)
{
	int n = sendto(fd, b, len, 0, NULL, 0);
	if (n == -1) {	/* fail */
		DEBUG(2, "Can't send %d bytes: %s", len, strerror(errno));
	}
	return n;
}

static int recv_packet(int fd, void *buf)
{
	int n = recvfrom(fd, buf, MAXBUF, 0, NULL, NULL);
	DEBUG(2, "Received %d bytes", n);
	return n;
}

static int max_pkts(void)
{
	return multi_accept;
}

#else	/* HAVE_NET_NETMAP_USER_H */

#include <net/if_dl.h>
#include <ifaddrs.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

static struct nm_desc *d;

static int dsr_init_os(char *dsr_if)
{
	int fd;
	struct ifaddrs *ifa, *a;
	struct sockaddr_dl *dl;
	if (getifaddrs(&ifa)) {
		error("Can't get list of interfaces: %s", strerror(errno));
	}
	for (a = ifa; a; a = a->ifa_next) {
		if ((a->ifa_addr->sa_family == AF_LINK) &&
		    (strcmp(a->ifa_name, dsr_if) == 0)) {
			break;
		}
	}
	if (a == NULL) {
		error("Can't find interface %s", dsr_if);
	}
	dl = (struct sockaddr_dl *)a->ifa_addr;
	memcpy(our_hw_addr, dl->sdl_data+dl->sdl_nlen, 6);
	DEBUG(2, "Our hw addr: %s\n", mac2str(our_hw_addr));
	char ifname[100];
	snprintf(ifname, sizeof ifname, "netmap:%s", dsr_if);
	d = nm_open(ifname, NULL, 0, 0);
	DEBUG(2, "first_tx_ring = %d, last_tx_ring = %d, first_rx_ring = %d, last_rx_ring = %d",
	d->first_tx_ring, d->last_tx_ring, d->first_rx_ring, d->last_rx_ring);
	fd = NETMAP_FD(d);
	buf = pen_malloc(MAXBUF);
	return fd;
}

static int send_packet(int fd, const void *b, int len)
{
	int n = nm_inject(d, b, len);
	if (n == 0) {	/* fail */
		DEBUG(2, "Can't send %d bytes", len);
		return -1;
	}
	return n;
}

static int recv_packet(int fd, void *buf)
{
	int n;
	struct nm_pkthdr h;
	uint8_t *b = nm_nextpkt(d, &h);
	if (b == NULL) return -1;
	n = h.caplen;
	DEBUG(2, "Received %d bytes", n);
	memcpy(buf, b, n);
	return n;
}

static int max_pkts(void)
{
	int in, out, m;

	m = multi_accept;
	in = nm_ring_space(NETMAP_RXRING(d->nifp, 0));
	if (in < m) m = in;
	out = nm_ring_space(NETMAP_TXRING(d->nifp, 0));
	if (out < m) m = out;
	DEBUG(3, "multi_accept = %d, in = %d, out = %d => m = %d", multi_accept, in, out, m);
	return m;
}

#endif

/* returns a raw socket or -1 for failure */
int dsr_init(char *dsr_if, char *listenport)
{
	char *dsr_ip, *dsr_port;

	dsr_ip = strtok(listenport, ":");
	dsr_port = strtok(NULL, ":");
	if (dsr_port) port = atoi(dsr_port);
	else port = 0;

	if (inet_aton(dsr_ip, &our_ip_addr) == 0) {
		debug("Address %s is not valid", dsr_ip);
		return -1;
	}

	return dsr_init_os(dsr_if);
}

void send_arp_request(int fd, struct in_addr *a)
{
debug("MAC_DST(%p) = %p", buf, MAC_DST(buf));
	memset(MAC_DST(buf), 0xff, 6);
	memcpy(MAC_SRC(buf), our_hw_addr, 6);
	*ETHERTYPE(buf) = htons(0x0806);
	*ARP_HTYPE(buf) = htons(1);
	*ARP_PTYPE(buf) = htons(0x0800);
	*ARP_HLEN(buf) = 6;
	*ARP_PLEN(buf) = 4;
	*ARP_OPER(buf) = htons(1);
	memcpy(ARP_SHA(buf), our_hw_addr, 6);
	memset(ARP_SPA(buf), 0, 4);
	memset(ARP_THA(buf), 0, 6);
	memcpy(ARP_TPA(buf), a, 4);
	hexdump(buf, 42);
	DEBUG(2, "Sending arp request");
	send_packet(fd, buf, 42);
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

/* returns 1 if this is an arp request for us, 0 otherwise */
static int our_arp(uint16_t arp_htype, uint16_t arp_ptype, uint16_t arp_oper, struct sockaddr_in *dest)
{
	if ((arp_htype != 1) || (arp_ptype != 0x0800) || (arp_oper != 1)) return 0;

	if (memcmp(&dest->sin_addr.s_addr, &our_ip_addr, 4) == 0) return 1;

	return match_acl(tarpit_acl, (struct sockaddr_storage *)dest);
}

static void arp_frame(int fd, int n)
{
	uint16_t arp_htype, arp_ptype, arp_oper;
	struct sockaddr_in dest;
	memcpy(&dest.sin_addr.s_addr, ARP_TPA(buf), 4);
	dest.sin_family = AF_INET;
	DEBUG(2, "ARP");
	arp_htype = ntohs(*ARP_HTYPE(buf));
	arp_ptype = ntohs(*ARP_PTYPE(buf));
	arp_oper = ntohs(*ARP_OPER(buf));
	DEBUG(2, "Hardware type: %d / %s", arp_htype,
		arp_htype == 1 ? "Ethernet" : "Other");
	DEBUG(2, "Protocol type: 0x%x / %s", arp_ptype,
		arp_ptype == 0x0800 ? "IPv4" : "Other");
	DEBUG(2, "Operation: %d / %s", arp_oper,
		arp_oper == 1 ? "Request" : "Reply");

	DEBUG(2, "Sender hardware address: %s", mac2str(ARP_SHA(buf)));
	DEBUG(2, "Sender protocol address: %s", inet_ntoa(*ARP_SPA(buf)));
	DEBUG(2, "Target hardware address: %s", mac2str(ARP_THA(buf)));
	DEBUG(2, "Target protocol address: %s", inet_ntoa(*ARP_TPA(buf)));
	if (our_arp(arp_htype, arp_ptype, arp_oper, &dest)) {
		hexdump(buf, n);
		DEBUG(2, "We should reply to this.");
		memcpy(MAC_DST(buf), ARP_SHA(buf), 6);
		memcpy(MAC_SRC(buf), our_hw_addr, 6);
		*ARP_OPER(buf) = htons(2);
		memcpy(ARP_THA(buf), ARP_SHA(buf), 6);
		memcpy(ARP_TPA(buf), ARP_SPA(buf), 4);
		memcpy(ARP_SHA(buf), our_hw_addr, 6);
//		memcpy(ARP_SPA(buf), &our_ip_addr, 4);
		memcpy(ARP_SPA(buf), &dest.sin_addr.s_addr, 4);
		DEBUG(2, "Sending %d bytes", n);
		n = send_packet(fd, buf, n);
	} else if ((arp_htype == 1) &&
		   (arp_ptype == 0x0800) &&
		   (arp_oper == 2)) {
		store_hwaddr(ARP_SPA(buf), ARP_SHA(buf));
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
	int *s;			/* how many slots should each server occupy */
	int ls;			/* number of live, available servers */
	int tw;			/* total weights of all available servers */
	int w;

	DEBUG(3, "rebuild_hash_index()");
	s = pen_malloc(nservers*sizeof *s);
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
		free(s);
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

	/* finally claim that the hash index is up to date */
	server_alg |= ALG_HASH_VALID;
	free(s);
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
		if (!rebuild_hash_index()) return NO_SERVER;	/* failure */
	}
	i = hash_index[h];
	DEBUG(3, "select_server returning server %d for hash %d", i, h);
	return i;
}


static int ipv4_frame(int fd, int n)
{
	uint8_t ipv4_protocol;
	uint8_t ipv4_ihl;
	uint16_t src_port, dst_port;
	int server;
	struct sockaddr_in dest;

	DEBUG(2, "IPv4");
	ipv4_ihl = ((*IPV4_IHL(buf)) & 0xf)*4;
	ipv4_protocol = *IPV4_PROTOCOL(buf);
	DEBUG(2, "IPv4 header size: %d bytes", ipv4_ihl);
	DEBUG(2, "Protocol: %d / %s", ipv4_protocol, proto2str(ipv4_protocol));
	DEBUG(2, "Sender IPv4 address: %s", inet_ntoa(*IPV4_SRC(buf)));
	DEBUG(2, "Destination IPv4 address: %s", inet_ntoa(*IPV4_DST(buf)));

	dest.sin_family = AF_INET;
	dest.sin_addr = *IPV4_DST(buf);

	if (udp) {
		DEBUG(3, "Doing udp");
		if ((ipv4_protocol == 17) &&
		    (*(uint32_t *)IPV4_DST(buf) == (uint32_t)our_ip_addr.s_addr)) {
			DEBUG(2, "We should forward this.");
			src_port = htons(*UDP_SRC_PORT(buf, ipv4_ihl));
			dst_port = htons(*UDP_DST_PORT(buf, ipv4_ihl));
			server = select_server(IPV4_SRC(buf), src_port);
			if (server == NO_SERVER) {
				debug("Dropping frame, nowhere to put it");
				return -1;
			}
			if (!real_hw_known(server)) {
				DEBUG(2, "Real hw addr unknown");
				return -1;
			}
			DEBUG(2, "Source port = %d, destination port = %d",
				src_port, dst_port);
			if (port == 0 || dst_port == port) {
				memcpy(MAC_DST(buf), servers[server].hwaddr, 6);
				memcpy(MAC_SRC(buf), our_hw_addr, 6);
				DEBUG(2, "Sending %d bytes", n);
				n = send_packet(fd, buf, n);
			}
		}
	} else {	/* not udp, i.e. tcp */
		DEBUG(3, "Doing tcp");
		if (ipv4_protocol == 6) {
			if (match_acl(tarpit_acl, (struct sockaddr_storage *)&dest)) {
				struct pseudo_header ph;
				int i;
				unsigned char src_mac[6];
				uint32_t seq_nr;
				uint16_t flags = ntohs(*TCP_FLAGS(buf, ipv4_ihl));
				uint32_t checksum;
				uint16_t *csp;

				DEBUG(2, "Tarpitting: flags = 0x%x");
				if ((flags & 0x0002) == 0) return 0;		/* not SYN */
				/* fill in the pseudo header fields */
				memcpy(&ph.src, IPV4_DST(buf), 4);
				memcpy(&ph.dst, IPV4_SRC(buf), 4);
				ph.zero = 0;		/* :P */
				ph.proto = 6;	/* tcp */
				ph.length = htons(40);		/* 5 32-bit words */

				DEBUG(2, "We should tarpit this");
				/* reverse everything to make the syn+ack frame */
				/* reverse mac addresses */
				memcpy(src_mac, MAC_SRC(buf), 6);
				memcpy(MAC_SRC(buf), MAC_DST(buf), 6);
				memcpy(MAC_DST(buf), src_mac, 6);
				/* reverse ip addresses */
				*IPV4_DST(buf) = *IPV4_SRC(buf);
				*IPV4_SRC(buf) = dest.sin_addr;
				/* reverse port numbers */
				src_port = ntohs(*TCP_SRC_PORT(buf, ipv4_ihl));
				*TCP_SRC_PORT(buf, ipv4_ihl) = *TCP_DST_PORT(buf, ipv4_ihl);
				*TCP_DST_PORT(buf, ipv4_ihl) = htons(src_port);
				/* reverse sequence numbers */
				seq_nr = ntohl(*TCP_SEQ_NR(buf, ipv4_ihl));
				*TCP_SEQ_NR(buf, ipv4_ihl) = htonl(42);	/* our random number */
				*TCP_ACK_NR(buf, ipv4_ihl) = htonl(seq_nr+1);
				/* 5 words of tcp header and SYN+ACK */
				*TCP_FLAGS(buf, ipv4_ihl) = htons((5 << 12) | 0x0012);
				*TCP_CHECKSUM(buf, ipv4_ihl) = 0;
				*TCP_URGENT(buf, ipv4_ihl) = 0;
				checksum = 0;
				csp = (uint16_t *)&ph;
				for (i = 0; i < 6; i++) {
					checksum += ntohs(csp[i]);
				}
				csp = (uint16_t *)TCP_SRC_PORT(buf, ipv4_ihl);
				for (i = 0; i < 10; i++) {
					checksum += ntohs(csp[i]);
				}
				checksum = (checksum & 0xffff) + (checksum >> 16);
				checksum ^= 0xffff;
				*TCP_CHECKSUM(buf, ipv4_ihl) = htons(checksum);
				DEBUG(2, "Checksum = 0x%x", checksum);
				/* ignore options */
				uint8_t offset = (flags >> 12);
				DEBUG(2, "Offset = %d => %d bytes of options", offset, 4*(offset-5));
				uint8_t *options = TCP_OPTIONS(buf, ipv4_ihl);
				DEBUG(2, "Options start at %p", options);
				i = 0;
				for (i = 0; i < 4*(offset-5); i++) {
					options[i] = 0;
				}
				n = send_packet(fd, buf, n);
			} else if (*(uint32_t *)IPV4_DST(buf) == (uint32_t)our_ip_addr.s_addr) {
				DEBUG(2, "We should forward this.");
				src_port = ntohs(*TCP_SRC_PORT(buf, ipv4_ihl));
				dst_port = ntohs(*TCP_DST_PORT(buf, ipv4_ihl));
				server = select_server(IPV4_SRC(buf), src_port);
				if (server == NO_SERVER) {
					debug("Dropping frame, nowhere to put it");
					return -1;
				}
				if (!real_hw_known(server)) {
					DEBUG(2, "Real hw addr unknown");
					return -1;
				}
				DEBUG(2, "Source port = %d, destination port = %d",
					src_port, dst_port);
				if (port == 0 || dst_port == port) {
					memcpy(MAC_DST(buf), servers[server].hwaddr, 6);
					memcpy(MAC_SRC(buf), our_hw_addr, 6);
					DEBUG(2, "Sending %d bytes", n);
					n = send_packet(fd, buf, n);
				}
			}
		}
	}
	return 0;
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
	int i, type, n, limit;
	static int dirty_bytes = 0;
	struct l2_frame *l2p = (struct l2_frame *)buf;

	if (dirty_bytes) {
		DEBUG(1, "Retrying transmission of %d bytes", dirty_bytes);
		n = send_packet(fd, buf, dirty_bytes);
		if (n == -1) {
			DEBUG(2, "Failed again, discarding packet");
		}
	}

	limit = max_pkts();

	for (i = 0; i < limit; i++) {
		dirty_bytes = recv_packet(fd, buf);
		if (dirty_bytes == -1) {
			dirty_bytes = 0;
			break;
		}
		DEBUG(2, "MAC destination: %s", mac2str(l2p->mac_dst));
		DEBUG(2, "MAC source: %s", mac2str(l2p->mac_src));
		type = ntohs(l2p->ethertype);
		DEBUG(2, "EtherType: %s", type2str(type));
		switch (type) {
		case 0x0806:
			arp_frame(fd, dirty_bytes);
			break;
		case 0x0800:
			if (ipv4_frame(fd, dirty_bytes) == -1) {
				DEBUG(2, "Couldn't process frame, retry later");
				goto End;
			}
			break;
		default:
			DEBUG(2, "Other (%x)", type);
		}
		dirty_bytes = 0;
	}
End:
	DEBUG(2, "Processed %d frames, %d bytes remaining", i, dirty_bytes);
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
