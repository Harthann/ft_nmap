#include "ft_nmap.h"
#include "args.h"

char f_flood = 0;
char *prog_name = NULL;

int			get_ipv4_addr(void);

unsigned short checksum(void *addr, size_t count)
{
	unsigned short *ptr;
	unsigned long sum;

	ptr = addr;
	for (sum = 0; count > 1; count -= 2)
		sum += *ptr++;
	if (count > 0)
		sum += *(unsigned char *)ptr;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (~sum);
}

struct tcp4_pseudohdr {
	uint32_t		src;
	uint32_t		dst;
	uint8_t			zero;
	uint8_t			protocol;
	uint16_t		tcp_len;
};

uint16_t	tcp4_checksum(struct iphdr *iphdr, struct tcphdr *tcphdr, uint8_t *data, int data_len)
{
	struct tcp4_pseudohdr	tcpphdr = {
		.src = iphdr->saddr,
		.dst = iphdr->daddr,
		.zero = 0,
		.protocol = IPPROTO_TCP,
		.tcp_len = htons(sizeof(struct tcphdr) + data_len)
	};
	uint8_t					buf[65536];

	memcpy(buf, &tcpphdr, sizeof(struct tcp4_pseudohdr));
	memcpy(buf + sizeof(struct tcp4_pseudohdr), tcphdr, sizeof(struct tcphdr));
	memcpy(buf + sizeof(struct tcp4_pseudohdr) + sizeof(struct tcphdr), data, data_len);
	return (checksum(buf, sizeof(struct tcp4_pseudohdr) + sizeof(struct tcphdr) + data_len));
}

# define MAX_TTL	255
# define DATA_LEN	0

int			recv_tcp4(int sockfd, struct iphdr *iphdr)
{
	struct	sockaddr_in		addr;
	unsigned int			addr_len;
	void					*buffer;
	int						len;
	struct tcphdr			*tcphdr;
	struct iphdr			*iphdr_rcv;

	len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;
	buffer = malloc(len);
	if (!buffer)
		return ENOMEM;
	if (recvfrom(sockfd, buffer, len, 0, (struct sockaddr *)&addr, &addr_len) < 0)
	{
		fprintf(stderr, "recvfrom: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	tcphdr = buffer + sizeof(struct iphdr);
	iphdr_rcv = buffer;
	if (iphdr_rcv->saddr == iphdr->daddr && tcphdr->syn && tcphdr->ack)
		printf("%d/tcp\n", ntohs(tcphdr->source));
	else if (iphdr_rcv->saddr != iphdr->daddr)
	{
		free(buffer);
		return EXIT_FAILURE;
	}
	free(buffer);
	return EXIT_SUCCESS;
}

int			send_tcp4(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, int dst_port)
{
	void			*buffer;
	void			*data;
	struct tcphdr	*tcphdr;

	iphdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;
	buffer = calloc(iphdr->tot_len, sizeof(uint8_t));
	if (!buffer)
		return ENOMEM;
	tcphdr = buffer + sizeof(struct iphdr);
	data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
	memcpy(buffer, iphdr, sizeof(struct iphdr));
	tcphdr->source = htons(33450);
	tcphdr->dest = htons(dst_port);
	tcphdr->syn = 1;
	tcphdr->window = htons(1024);
	tcphdr->doff = (uint8_t)(sizeof(struct tcphdr) / sizeof(uint32_t)); // size in 32 bit word
//	memset(data, 42, DATA_LEN);
	tcphdr->check = tcp4_checksum(iphdr, tcphdr, data, DATA_LEN);
	if (sendto(sockfd, buffer, iphdr->tot_len, 0, (struct sockaddr *)sockaddr, sizeof(struct sockaddr)) < 0)
		return EXIT_FAILURE;
	free(buffer);
	return EXIT_SUCCESS;
}

int			poc_tcp(char *target)
{
	sockfd_t			socks;

	socks.sockfd_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (socks.sockfd_tcp < 0)
	{
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		return EXIT_FAILURE;
	}
	int on = 1;
	setsockopt(socks.sockfd_tcp, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on));
//	struct timeval tv = {
//		.tv_sec = 2,
//		.tv_usec = 0
//	};
//	setsockopt(socks.sockfd_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	uint32_t	src_addr;
	uint32_t	dst_addr;

	src_addr = get_ipv4_addr();
	inet_pton(AF_INET, target, &dst_addr);
	struct sockaddr_in sockaddr;
	sockaddr.sin_addr.s_addr = dst_addr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = 0;
	struct iphdr	iphdr = {
		.version = 4,
		.ihl = sizeof(struct iphdr) / sizeof(uint32_t),
		.tos = 0,
		.tot_len = 0,
		.id = 0,
		.frag_off = 0,
		.ttl = 255,
		.protocol = IPPROTO_TCP,
		.check = 0, // filled by kernel
		.saddr = src_addr,
		.daddr = dst_addr
	};
// ===
	struct pollfd		fds[1];

	memset(fds, 0, sizeof(fds));
	fds[0].fd = socks.sockfd_tcp;
	fds[0].events = POLLIN | POLLOUT | POLLERR;

	int i = 1;
	while (true)
	{
		int res = poll(fds, 1, 2000);
		if (res > 0)
		{
			if (fds[0].revents & POLLIN)
				recv_tcp4(socks.sockfd_tcp, &iphdr);
			else if (fds[0].revents & POLLOUT && i <= 1024)
			{
				int ret = send_tcp4(socks.sockfd_tcp, &sockaddr, &iphdr, i++);
				if (ret == ENOMEM)
					fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
				else if (ret == EXIT_FAILURE)
					fprintf(stderr, "%s: sendto: %s\n", prog_name, strerror(errno));
			}
			else if (i > 1024 && fds[0].revents & POLLOUT)
				fds[0].events = POLLIN | POLLERR;
		}
		else if (!res)
			break ;
	}
// ===
	return EXIT_SUCCESS;
}

int			get_ipv4_addr(void)
{
	int					addr;
	struct sockaddr_in	*paddr;
	struct ifaddrs		*ifap, *tmp;

	getifaddrs(&ifap);
	tmp = ifap;
	while (tmp)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET && !(tmp->ifa_flags & IFF_LOOPBACK))
		{
			paddr = (struct sockaddr_in *)tmp->ifa_addr;
			inet_pton(AF_INET, inet_ntoa(paddr->sin_addr), &addr);
			break ;
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(ifap);
	return (addr);
}

char		*resolve_hostname(char *hostname)
{
	struct addrinfo *res;
	struct addrinfo hints;
	char			*buffer;
	char			*addr;

	addr = NULL;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	if (!getaddrinfo(hostname, NULL, &hints, &res))
	{
		addr = malloc(MAX_ADDR_SIZE);
		if (!addr)
			return (NULL);
		buffer = inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr);
		strcpy(addr, buffer);
		freeaddrinfo(res);
	}
	return (addr);
}

void		nmap(char *target)
{
	char			*ip_addr;

	ip_addr = resolve_hostname(target);
	if (!ip_addr)
	{
		fprintf(stderr, "%s: Failed to resolve \"%s\".\n", prog_name, target);
		return ;
	}
	poc_tcp(ip_addr);
	free(ip_addr);
}

void		signature(void)
{
	struct tm		*info;
	struct timeval	tv;
	time_t			t;

	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
	info = localtime(&t);
	printf("Starting %s %s at %d-%02d-%02d %02d:%02d CEST\n", PROG_NAME, VERSION,
info->tm_year + 1900, info->tm_mon + 1, info->tm_mday, info->tm_hour, info->tm_min);
}

void		signal_handler(int signum)
{
	printf("\b\b  \b\b\n");
	exit(128 + signum);
}

void		handling_signals()
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &signal_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}

int			main(int ac, char **av)
{
	prog_name = strdup((*av[0]) ? av[0] : PROG_NAME);
	if (!prog_name)
	{
		fprintf(stderr, "%s: %s\n", PROG_NAME, strerror(errno));
		return EXIT_FAILURE;
	}
	if (parse_arg(ac - 1, av + 1) != 0)
	{
		free(prog_name);
		return EXIT_FAILURE;
	}
	signature();
	handling_signals();
	for (size_t i = 0; g_arglist[i]; i++)
		nmap(g_arglist[i]);
	free(prog_name);
	return EXIT_SUCCESS;
}
