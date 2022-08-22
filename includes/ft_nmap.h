#ifndef FT_NMAP
#define FT_NMAP

/*	Sockets headers */
# include <arpa/inet.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/time.h>
# include <netdb.h>

# include <netinet/in.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>

# include <net/if.h>
# include <asm/byteorder.h>
# include <ifaddrs.h>

# include <poll.h>

/* Utils headers */
# include <errno.h>
# include <signal.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdbool.h>
# include <string.h>
# include <time.h>
# include <unistd.h>

# include "logs.h"

# define PROG_NAME		"ft_nmap"
# define VERSION		"alpha 0.1"

# define MAX_TTL	255
# define DATA_LEN	0

# define MAX_ADDR_SIZE	64

typedef struct	sockfd_s {
	int			sockfd_tcp;
}				sockfd_t;


struct scan_s {
	struct iphdr	*iphdr;
	struct tcphdr	*tcphdr;

	struct scan_s	*next;
};

/*
** Macro to cast tcphdr and gather or set tcp flag easilu
*/
#define TCP_FLAG(tcphdr) *((uint8_t*)tcphdr + 13)
#define SET_TCPFLAG(tcphdr, flag) (*((uint8_t*)tcphdr + 13) = flag)

/*
** Definition for tcp flag according to linux headers
*/
#if defined(__LITTLE_ENDIAN_BITFIELD)
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x30
#define CWR 0x40
#elif defined(__BIG_ENDIAN_BITFIELD)
#define FIN 0x40
#define SYN 0x30
#define RST 0x20
#define PSH 0x10
#define ACK 0x08
#define URG 0x04
#define ECE 0x02
#define CWR 0x01
#endif

int			get_ipv4_addr(void);

struct scan_s *new_scanentry(struct scan_s *head, void *buffer);
void print_scanlist(struct scan_s *scanlist);
bool	find_scan(void* buffer, struct scan_s *scanlist);
int		tcp4_checksum(struct iphdr *iphdr, struct tcphdr *tcphdr, uint8_t *data, int data_len, uint16_t *sum);

#endif
