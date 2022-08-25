#include "ft_nmap.h"
#include "args.h"

char				*prog_name = NULL;

/*
** Target is a string containing either the ip or the domain name of the target
** Ports[0] correspond to the first port to scan and ports[1] the last
** Performuing ports[1] - ports[0] should give the number of ports
** This number should lend between 1 and 1024
*/
void		nmap(char *target, uint32_t *portrange, uint32_t nb_ports)
{
	char			*dev_name;
	sockfd_t		socks;
	uint32_t		dst_addr;
	char			*target_ip;

	init_socket(target, &socks, &target_ip, &dst_addr);
	dev_name = get_device();
	if (!dev_name) {
		return ;
	}
// ===
// ===
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
	if (get_ipv4_addr((int *)&iphdr.saddr, dev_name) == EXIT_FAILURE) {
		free(dev_name);
		return ;
	}

	char	errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32			mask;
	bpf_u_int32			net;

	if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_loopkupnet: %s\n", prog_name, errbuf);
		net = 0;
		mask = 0;
	}

	t_port_status *ports = scan_syn(socks.sockfd_tcp, &sockaddr, &iphdr, net, portrange, nb_ports);

	print_report(ports, nb_ports, target, target_ip);

	free(ports);
	free(dev_name);
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
		.portrange = NULL
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
		nmap(config.targets[i], config.portrange, config.nb_ports);
	free(config.portrange);
	free(prog_name);
	return EXIT_SUCCESS;
}
