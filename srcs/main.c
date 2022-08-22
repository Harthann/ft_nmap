#include "ft_nmap.h"
#include "args.h"

char *prog_name = NULL;

int			recv_syn(int sockfd, struct scan_s *scanlist, t_port_status *ports, int nb_port)
{
	void					*buffer;
	int						len;
	struct tcphdr			*tcphdr;
//	struct iphdr			*iphdr_rcv;

	len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;
	buffer = malloc(len);
	if (!buffer)
		return -ENOMEM;

	if (recvfrom(sockfd, buffer, len, 0, NULL, NULL) < 0)
	{
		free(buffer);
		fprintf(stderr, "recvfrom: %s\n", strerror(errno));
		free(buffer);
		return EXIT_FAILURE;
	}

//	iphdr_rcv = buffer;

/*
** Perform a check if the response correspond to one of our scan
** If so check the responses flag and print scan result
*/
	tcphdr = buffer + sizeof(struct iphdr);
	if (find_scan(buffer, scanlist)) {
		if (TCP_FLAG(tcphdr) == (SYN | ACK))
		{
			for (int i = 0; i < nb_port; i++)
			{
				if (ports[i].port == htons(tcphdr->source))
					ports[i].status = STATUS_OPEN;
			}
		}
	}
	free(buffer);
	return EXIT_SUCCESS;
}

int			send_tcp4(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, int dst_port, struct scan_s **scanlist, uint16_t flag)
{
	void			*buffer;
	void			*data;
	struct tcphdr	*tcphdr;

	iphdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;

	buffer = calloc(iphdr->tot_len, sizeof(uint8_t));
	if (!buffer)
		return -ENOMEM;

	tcphdr = buffer + sizeof(struct iphdr);
	data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
	memcpy(buffer, iphdr, sizeof(struct iphdr));

	tcphdr = buffer + sizeof(struct iphdr);
	tcphdr->source = htons(33450);
	tcphdr->dest = htons(dst_port);
	tcphdr->syn = 1;
	SET_TCPFLAG(tcphdr, flag);
	tcphdr->window = htons(1024);
	tcphdr->doff = (uint8_t)(sizeof(struct tcphdr) / sizeof(uint32_t)); // size in 32 bit word

//	memset(data, 42, DATA_LEN);
	if (tcp4_checksum(iphdr, tcphdr, data, DATA_LEN, &tcphdr->check))
	{
		free(buffer);
		return -ENOMEM;
	}
	
	if (sendto(sockfd, buffer, iphdr->tot_len, 0, (struct sockaddr *)sockaddr, sizeof(struct sockaddr)) < 0)
	{
		free(buffer);
		return EXIT_FAILURE;

	}
	*scanlist = new_scanentry(*scanlist, buffer);

	return EXIT_SUCCESS;
}

t_port_status	*scan_syn(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, uint32_t port_start, uint32_t port_end)
{
	struct scan_s		*scanlist = NULL;
	struct pollfd		fds[1];
	uint32_t			nb_ports;
	t_port_status		*ports;

	nb_ports = (port_end - port_start) + 1;
	ports = calloc(nb_ports, sizeof(t_port_status));
	if (!ports)
	{
		fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
		return NULL;
	}
	for (uint32_t i = 0; i < port_end - port_start - 1; i++)
		ports[i].port = port_start + i;
	memset(fds, 0, sizeof(fds));
	fds[0].fd = sockfd;
	fds[0].events = POLLIN | POLLOUT | POLLERR;

	uint32_t i = port_start;
	while (true)
	{
		int res = poll(fds, 1, 1000);
		if (res > 0)
		{
			if (fds[0].revents & POLLIN)
				recv_syn(sockfd, scanlist, ports, nb_ports);
			else if (fds[0].revents & POLLOUT && i <= port_end)
			{
				int ret = send_tcp4(sockfd, sockaddr, iphdr, i++, &scanlist, SYN);
				if (ret == -ENOMEM)
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

//	print_scanlist(scanlist);
	return ports;
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
	sockfd_t		socks;
	uint32_t		dst_addr;
	char			*target_ip;

	target_ip = resolve_hostname(target);
	if (!target_ip)
	{
		fprintf(stderr, "%s: Failed to resolve \"%s\".\n", prog_name, target);
		return ;
	}
	inet_pton(AF_INET, target_ip, &dst_addr);
	socks.sockfd_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (socks.sockfd_tcp < 0)
	{
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		free(target_ip);
		return ;
	}
	int on = 1;
	setsockopt(socks.sockfd_tcp, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on));

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
		.saddr = get_ipv4_addr(), // TODO: if not ip ?
		.daddr = dst_addr
	};
	t_port_status *ports = scan_syn(socks.sockfd_tcp, &sockaddr, &iphdr, 1, 1024);
	if (!ports)
	{
		free(target_ip);
		return ;
	}
	printf("%s scan report for %s (%s)\n", prog_name, target, target_ip);
	printf("PORT      STATUS            SERVICE\n");
	for (uint32_t i = 0; i < 1024; i++)
	{
		if (ports[i].status & STATUS_OPEN)
		{
			struct servent* servi = getservbyport(htons(ports[i].port), "tcp");
			int			n;
			printf("%d/tcp%n", ports[i].port, &n);
			printf("%*copen%*c", 10 - n, ' ', 18 - 4, ' ');
			if (servi)
				printf("%s\n", servi->s_name);
			else
				printf("unknown\n");
		}
	}
	free(ports);
	free(target_ip);
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

	memset(&sa, 0, sizeof(struct sigaction));
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
