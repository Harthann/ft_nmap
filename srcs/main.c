#include "ft_nmap.h"
#include "args.h"

char				*prog_name = NULL;

/*
** Target is a string containing either the ip or the domain name of the target
** Ports[0] correspond to the first port to scan and ports[1] the last
** Performuing ports[1] - ports[0] should give the number of ports
** This number should lend between 1 and 1024
*/
void		nmap(char *target, scanconf_t *config)//, uint32_t *portrange, uint32_t nb_ports)
{
	sockfd_t		socks;
	char			*dev_name;
	char			*target_ip;

/*
** General purpose structure ip and sockaddr
*/
	struct iphdr iphdr = {
		.version = 4,
		.ihl = sizeof(struct iphdr) / sizeof(uint32_t),
		.tos = 0,
		.tot_len = 0,
		.id = 0,
		.frag_off = 0,
		.ttl = 255,
		.protocol = 0,
		.check = 0, // filled by kernel
		.saddr = 0,
	};
	struct sockaddr_in sockaddr = {
		.sin_family = AF_INET,
		.sin_port = 0
	};

/*
** Initialize socket for tcp packet scan
*/
	if (init_socket(&socks.sockfd_tcp, IPPROTO_TCP) == EXIT_FAILURE) {
		return ;
	}
	if (init_socket(&socks.sockfd_udp, IPPROTO_UDP) == EXIT_FAILURE) {
		return ;
	}

/*
** Resolve hostname and get ip in string format and uint format
** Once ip is resolved as uint, fill sockaddr struct with it's value
*/
	target_ip = resolve_hostname(target);
	if (!target_ip) {
		fprintf(stderr, "%s: Failed to resolve \"%s\".\n", prog_name, target);
		return ;
	}
	inet_pton(AF_INET, target_ip, &iphdr.daddr);
	sockaddr.sin_addr.s_addr = iphdr.daddr;

/*
** Perform a device lookup and initialize ip packet
** Ip source will be initialized with interface ip of devo_name
*/
	char				errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32			mask;
	bpf_u_int32			net;


	dev_name = get_device();
	if (!dev_name) {
		free(target_ip);
		return ;
	}
	if (get_ipv4_addr((int *)&iphdr.saddr, dev_name) == EXIT_FAILURE) {
		free(target_ip);
		free(dev_name);
		return ;
	}
	if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_loopkupnet: %s\n", prog_name, errbuf);
		net = 0;
		mask = 0;
	}

/*
** Everything is initialized, we can now perfrom each scan
*/
//<<<<<<< HEAD
//	t_port_status *ports;
//
//	if (verbose & SCAN_SYN) {
//		printf("SYN SCAN\n");
//		ports = scan_syn(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		print_report(ports, config->nb_ports, target, target_ip);
//		free(ports);
//	}
//
//	if (verbose & SCAN_NULL) {
//		printf("NULL SCAN\n");
//		ports = scan_null(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		print_report(ports, config->nb_ports, target, target_ip);
//		free(ports);
//	}
//
//	if (verbose & SCAN_ACK) {
//		printf("ACK SCAN\n");
//		ports = scan_ack(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		print_report(ports, config->nb_ports, target, target_ip);
//		free(ports);
//	}
//
//	if (verbose & SCAN_FIN) {
//		printf("FIN SCAN\n");
//		ports = scan_fin(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		print_report(ports, config->nb_ports, target, target_ip);
//		free(ports);
//	}
//
//	if (verbose & SCAN_XMAS) {
//		printf("XMAS SCAN\n");
//		ports = scan_xmas(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		print_report(ports, config->nb_ports, target, target_ip);
//		free(ports);
//	}
//
//	if (verbose & SCAN_UDP) {
//		printf("UDP SCAN\n");
//		ports = scan_udp(socks.sockfd_udp, &sockaddr, &iphdr, net, config);
//		print_report(ports, config->nb_ports, target, target_ip);
//		free(ports);
//	}
//=======
	int nb_scans = 6;
	t_scans			scans[6] = {
		{scan_syn, NULL},
		{scan_null, NULL},
		{scan_ack, NULL},
		{scan_fin, NULL},
		{scan_xmas, NULL},
		{scan_udp, NULL}
	};


	//ports = calloc(sizeof(t_port_status *), nb_scans);
	//if (!ports)
	//{
	//	fprintf(stderr, "%s: malloc: %s\n", prog_name, strerror(errno));
	//	free(dev_name);
	//	free(target_ip);
	//	return ;
	//}
	

	for (int i = 0; i < 5; i++) {
		if (verbose & (2 << i))
			scans[i].ports = scans[i].scan_function(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
		if (verbose & VERBOSITY)
			print_report(scans[i].ports, config->nb_ports, target, target_ip, "tcp");
	}

//	if (verbose & SCAN_SYN) {
//		printf("SYN SCAN\n");
//		ports[0] = scan_syn(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		if (verbose & VERBOSITY)
//			print_report(ports[0], config->nb_ports, target, target_ip, "tcp");
//	}
//
//	if (verbose & SCAN_NULL) {
//		printf("NULL SCAN\n");
//		ports[1] = scan_null(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		if (verbose & VERBOSITY)
//			print_report(ports[1], config->nb_ports, target, target_ip, "tcp");
//	}
//
//	if (verbose & SCAN_ACK) {
//		printf("ACK SCAN\n");
//		ports[2] = scan_ack(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		if (verbose & VERBOSITY)
//			print_report(ports[2], config->nb_ports, target, target_ip, "tcp");
//	}
//
//	if (verbose & SCAN_FIN) {
//		printf("FIN SCAN\n");
//		ports[3] = scan_fin(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		if (verbose & VERBOSITY)
//			print_report(ports[3], config->nb_ports, target, target_ip, "tcp");
//	}
//
//	if (verbose & SCAN_XMAS) {
//		printf("XMAS SCAN\n");
//		ports[4] = scan_xmas(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
//		if (verbose & VERBOSITY)
//			print_report(ports[4], config->nb_ports, target, target_ip, "tcp");
//	}

	if (verbose & SCAN_UDP)
	{
		scans[5].ports = scans[5].scan_function(socks.sockfd_udp, &sockaddr, &iphdr, net, config);
		if (verbose & VERBOSITY)
			print_report(scans[5].ports, config->nb_ports, target, target_ip, "udp");
	}

	t_port_status *final_report;
	final_report = malloc(config->nb_ports * sizeof(t_port_status));
	if (!final_report)
	{
		fprintf(stderr, "%s: malloc: %s\n", prog_name, strerror(errno));
		for (int i = 0; i < nb_scans; i++)
			free(scans[i].ports);
		free(dev_name);
		free(target_ip);
		return ;
	}

	for (uint32_t i = 0; i < config->nb_ports; i++)
	{
		final_report[i].port = scans[0].ports[i].port;
		if (verbose & SCAN_SYN && (scans[0].ports[i].flags & OPEN || scans[0].ports[i].flags & CLOSE)) // SYN SCAN OPEN OR CLOSE
			final_report[i].flags = scans[0].ports[i].flags;
		else
		{
			int all_flags[16] = {0};
			for (int j = 1; j < nb_scans - 1; j++)
			{
				if (verbose & (2 << j))
					all_flags[scans[j].ports[i].flags]++;
			}
			int max_flags = 0;
			int max_value = -1;
			for (int j = 0; j < 16; j++)
			{
				if (max_value < all_flags[j])
				{
					max_value = all_flags[j];
					max_flags = j;
				}
			}
			final_report[i].flags = max_flags;
		}
	}
	print_report(final_report, config->nb_ports, target, target_ip, "tcp");
	print_report(scans[5].ports, config->nb_ports, target, target_ip, "udp");

	free(final_report);
	for (int i = 0; i < nb_scans; i++)
		free(scans[i].ports);
//	free(ports);


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
		.portrange = NULL,
		.nb_threads = 0,
		.timeout = 1, // TODO: ping to know how many
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
		freeiplist(config.targets);
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
		nmap(config.targets[i], &config);

	freeiplist(config.targets);
	free(config.portrange);
	free(prog_name);
	return EXIT_SUCCESS;
}
