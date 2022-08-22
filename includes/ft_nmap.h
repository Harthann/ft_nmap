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
# include <ifaddrs.h>

# include <poll.h>

/* Utils headers */
# include <errno.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdbool.h>
# include <string.h>
# include <time.h>

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


int			get_ipv4_addr(void);

struct scan_s *new_scanentry(struct scan_s *head, void *buffer);
void print_scanlist(struct scan_s *scanlist);
uint16_t	tcp4_checksum(struct iphdr *iphdr, struct tcphdr *tcphdr, uint8_t *data, int data_len);

#endif
