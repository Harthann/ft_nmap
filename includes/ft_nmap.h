#ifndef FT_NMAP
#define FT_NMAP

/*	Sockets headers */
# include <arpa/inet.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/time.h>
# include <netdb.h>

# include <netinet/if_ether.h>
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
# include <pthread.h>
# include <signal.h>
# include <stdio.h>
# include <stdlib.h>
# include <stdbool.h>
# include <string.h>
# include <time.h>
# include <unistd.h>

# include <pcap.h>
# include <pcap/sll.h>

# include "logs.h"

/*=== DEFINES ===*/
# define PROG_NAME		"ft_nmap"
# define VERSION		"alpha 0.1"

# define MAX_TTL	255
# define DATA_LEN	0
# define MAX_ADDR_SIZE	64

# define		SET_ACCESS		0x01
# define		OPEN			0x02
# define		CLOSE			0x00
# define		SET_FILTER		0x04
# define		FILTERED		0x08
# define		UNFILTERED		0x00

extern char *prog_name;

/*=== STRUCTURES ===*/
typedef struct scanconf_s {
	int			types;
	char		**targets;
	uint32_t	*portrange;
	uint32_t	nb_ports;
	uint32_t	nb_threads;
	int			timeout;
}	scanconf_t;


typedef struct	sockfd_s {
	int			sockfd_tcp;
	int			sockfd_udp;
}				sockfd_t;

/*
** Storage class to track each scan result for each ports
*/
typedef struct	s_port_status {
	int			port;
	uint8_t		flags;
}				t_port_status;

/*
** Storage struct to keep track of each tcp packet sended
*/
// TODO: add scan type ?
struct scan_s {
	void			*packet;
	struct scan_s	*next;
};

typedef struct	s_args_send {
	int					sockfd;
	struct sockaddr_in	sockaddr;
	struct iphdr		iphdr;
	t_port_status		*portrange;
	int					nb_ports;
	int					flags;
}				t_args_send;

/*=== MACROS ===*/

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

#define XMAS (FIN | URG | PSH)

/*=== PROTOTYPES ===*/

/* scans/syn.c */
void		callback_capture(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
t_port_status	*scan_syn(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, scanconf_t *config);
/* scans/fin.c */
t_port_status	*scan_fin(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, scanconf_t *config);
/* scans/xmas.c */
t_port_status	*scan_xmas(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, scanconf_t *config);
/* scans/null.c */
t_port_status	*scan_null(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, scanconf_t *config);
/* scans/ack.c */
t_port_status	*scan_ack(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, scanconf_t *config);

/* netutils.c */
char		*get_device(void);
int			get_ipv4_addr(int *addr, char *name);
char		*resolve_hostname(char *hostname);
int			init_socket(int *fd, int proto);

/* send.c */
int				thread_send(int sockfd, struct sockaddr_in * sockaddr, struct iphdr *iphdr, int flags, scanconf_t *config, t_port_status *ports, void *(fn(void *)), int nb_threads);
void		*send_tcp4_packets(void *args);
int			send_tcp4(int sockfd, struct sockaddr_in sockaddr, struct iphdr iphdr, int dst_port, uint16_t flag);

/* scanlist.c */
struct scan_s	*new_scanentry(struct scan_s *head, void *buffer);
void			print_scanlist(struct scan_s *scanlist);
void			free_scanlist(struct scan_s *scanlist);
bool			find_scan(void* buffer, struct scan_s *scanlist);


/* pcap_handlers.c */
int		pcap_setup_filter(pcap_t *handle, struct bpf_program *fp, bpf_u_int32 net, char *filter);

/* checksum.c */
int		tcp4_checksum(struct iphdr *iphdr, struct tcphdr *tcphdr, uint8_t *data, int data_len, uint16_t *sum);

/* signal.c */
void		handling_signals();
void		setup_pcap_exit(int seconds);

/* print_report.c */
void	print_report(t_port_status *ports, uint32_t nb_ports, char *target, char *target_ip);

#endif

