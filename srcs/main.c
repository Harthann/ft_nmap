#include "ft_nmap.h"
#include "args.h"

char *prog_name = NULL;

/*
** Target is a string containing either the ip or the domain name of the target
** Ports[0] correspond to the first port to scan and ports[1] the last
** Performuing ports[1] - ports[0] should give the number of ports
** This number should lend between 1 and 1024
*/
void		nmap(char *target, int portrange[2])
{
	pcap_if_t		*alldesvp, *dev;
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
	dev = get_device(&alldesvp);
	if (!dev)
	{
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
		.saddr = 0,
		.daddr = dst_addr
	};
	if (get_ipv4_addr((int *)&iphdr.saddr, dev) == EXIT_FAILURE)
	{
		pcap_freealldevs(alldesvp);
		free(target_ip);
		return ;
	}
	t_port_status *ports = scan_syn(socks.sockfd_tcp, &sockaddr, &iphdr, portrange[0], portrange[1]);
	if (!ports)
	{
		pcap_freealldevs(alldesvp);
		free(target_ip);
		return ;
	}
	printf("%s scan report for %s (%s)\n", prog_name, target, target_ip);
	printf("PORT      STATUS            SERVICE\n");
	for (uint32_t i = 0; i < ((uint32_t)portrange[1] - portrange[0] + 1); i++)
	{

		printf("Print port number: %u\n", portrange[0] + i);
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
	pcap_freealldevs(alldesvp);
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

int			main(int ac, char **av)
{
	scanconf_t	config = {
		.types = -1,
		.targets = NULL,
		.portrange = {1, 1024},
	};

	/*
	** Storing the program name for better printing
	*/
	prog_name = strdup((*av[0]) ? av[0] : PROG_NAME);
	if (!prog_name)
	{
		fprintf(stderr, "%s: %s\n", PROG_NAME, strerror(errno));
		return EXIT_FAILURE;
	}
	/*
	** Parse argument send to the program using ft_getopt
	*/
	if (parse_arg(ac - 1, av + 1, &config) != 0)
	{
		free(prog_name);
		return EXIT_FAILURE;
	}

	/*
	** Preparing the program to perform scans
	*/
	signature();
	handling_signals();

	/*
	** For each ip found inside arguments we'll perform a scan
	*/
	for (size_t i = 0; config.targets[i]; i++)
		nmap(config.targets[i], config.portrange);

	free(prog_name);
	return EXIT_SUCCESS;
}
