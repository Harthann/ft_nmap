#include "ft_nmap.h"
#include "args.h"

char				*prog_name = NULL;

t_port_status		*compute_scan_report(t_scans *scans, scanconf_t *config)
{
	t_port_status *final_report;

	final_report = malloc(config->nb_ports * sizeof(t_port_status));
	if (!final_report)
	{
		fprintf(stderr, "%s: malloc: %s\n", prog_name, strerror(errno));
		return (NULL);;
	}
	for (uint32_t i = 0; i < MAX_SCANS - 1; i++)
	{
		if (scans[i].ports != NULL)
		{
			for (uint32_t j = 0; j < config->nb_ports; j++)
				final_report[j].port = scans[i].ports[j].port;
			break ;
		}
	}
	for (uint32_t i = 0; i < config->nb_ports; i++)
	{
		if ((verbose & SCAN_SYN) &&
		((scans[N_SYN_SCAN].ports[i].flags & SET_ACCESS) || !(verbose & 0x7c))) // SYN SCAN OPEN OR CLOSE
			final_report[i].flags = scans[N_SYN_SCAN].ports[i].flags;
		else
		{
			int all_flags[16] = {0};
			for (int j = 1; j < MAX_SCANS - 1; j++)
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
	return (final_report);
}

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

	socks.sockfd_tcp = -1;
	socks.sockfd_udp = -1;
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
	if (verbose & 0x3f &&
init_socket(&socks.sockfd_tcp, IPPROTO_TCP) == EXIT_FAILURE)
		return ;
	if (verbose & SCAN_UDP &&
init_socket(&socks.sockfd_udp, IPPROTO_UDP) == EXIT_FAILURE)
		return ;

/*
** Resolve hostname and get ip in string format and uint format
** Once ip is resolved as uint, fill sockaddr struct with it's value
*/
	target_ip = resolve_hostname(target);
	if (!target_ip) {
		fprintf(stderr, "%s: Failed to resolve \"%s\".\n", prog_name, target);
		if (socks.sockfd_tcp != -1)
			close(socks.sockfd_tcp);
		if (socks.sockfd_udp != -1)
			close(socks.sockfd_udp);
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
		if (socks.sockfd_tcp != -1)
			close(socks.sockfd_tcp);
		if (socks.sockfd_udp != -1)
			close(socks.sockfd_udp);
		return ;
	}
	if (get_ipv4_addr((int *)&iphdr.saddr, dev_name) == EXIT_FAILURE) {
		free(target_ip);
		free(dev_name);
		if (socks.sockfd_tcp != -1)
			close(socks.sockfd_tcp);
		if (socks.sockfd_udp != -1)
			close(socks.sockfd_udp);
		return ;
	}
	if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_loopkupnet: %s\n", prog_name, errbuf);
		net = 0;
		mask = 0;
	}
	printf("Scanning %s (%s).", target, target_ip);
	fflush(stdout);
// ==> SCANNING <==
	t_scans			scans[MAX_SCANS] = {
		{scan_syn, NULL},
		{scan_null, NULL},
		{scan_ack, NULL},
		{scan_fin, NULL},
		{scan_xmas, NULL},
		{scan_udp, NULL}
	};

	for (int i = 0; i < MAX_SCANS - 1; i++) {
		if (verbose & (2 << i))
		{
			if (!(verbose & VERBOSITY))
				write(STDOUT_FILENO, ".", 1);
			scans[i].ports = scans[i].scan_function(socks.sockfd_tcp, &sockaddr, &iphdr, net, config);
			if (verbose & VERBOSITY)
			{
				if (i == N_SYN_SCAN)
					printf("-- VERBOSE --> SYN SCAN\n");
				else if (i == N_NULL_SCAN)
					printf("-- VERBOSE --> NULL SCAN\n");
				else if (i == N_ACK_SCAN)
					printf("-- VERBOSE --> ACK SCAN\n");
				else if (i == N_FIN_SCAN)
					printf("-- VERBOSE --> FIN SCAN\n");
				else if (i == N_XMAS_SCAN)
					printf("-- VERBOSE --> XMAS SCAN\n");
				print_report(scans[i].ports, config->nb_ports, "tcp");
			}
		}
	}

	if (verbose & SCAN_UDP)
	{
		if (!(verbose & VERBOSITY))
			write(STDOUT_FILENO, ".", 1);
		scans[N_UDP_SCAN].ports = scans[N_UDP_SCAN].scan_function(socks.sockfd_udp, &sockaddr, &iphdr, net, config);
		if (verbose & VERBOSITY)
		{
			printf("-- VERBOSE --> UDP SCAN\n");
			print_report(scans[N_UDP_SCAN].ports, config->nb_ports, "udp");
		}
	}
	if (!(verbose & VERBOSITY))
		write(STDOUT_FILENO, "\n", 1);
	t_port_status *final_report;

	if (verbose & 0x3f)
	{
		final_report = compute_scan_report(scans, config);
		if (!final_report)
		{
			for (int i = 0; i < MAX_SCANS; i++)
				free(scans[i].ports);
			free(dev_name);
			free(target_ip);
			if (socks.sockfd_tcp != -1)
				close(socks.sockfd_tcp);
			if (socks.sockfd_udp != -1)
				close(socks.sockfd_udp);
			return ;
		}
	}

	printf("%s scan report for %s (%s)\n", prog_name, target, target_ip);
	if (verbose & 0x3f)
	{
		print_report(final_report, config->nb_ports, "tcp");
		free(final_report);
	}
	if (verbose & SCAN_UDP)
		print_report(scans[N_UDP_SCAN].ports, config->nb_ports, "udp");

	printf("\n");

	for (int i = 0; i < MAX_SCANS; i++)
		free(scans[i].ports);
	free(dev_name);
	free(target_ip);
	if (socks.sockfd_tcp != -1)
		close(socks.sockfd_tcp);
	if (socks.sockfd_udp != -1)
		close(socks.sockfd_udp);
}

struct timeval		signature(void)
{
	struct tm		*info;
	struct timeval	tv;
	time_t			t;

	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
	info = localtime(&t);
	printf("Starting %s %s at %d-%02d-%02d %02d:%02d %s\n", PROG_NAME, VERSION,
info->tm_year + 1900, info->tm_mon + 1, info->tm_mday, info->tm_hour, info->tm_min, info->tm_zone);
	return (tv);
}

int			main(int ac, char **av)
{
	struct timeval	start;
	scanconf_t		config = {
		.types = -1,
		.targets = NULL,
		.portrange = NULL,
		.nb_threads = 0,
		.timeout = 1 // default
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
	if (parse_arg(ac - 1, av + 1, &config) == EXIT_FAILURE)
	{
		free(config.portrange);
		free(prog_name);
		freeiplist(config.targets);
		getopt_release();
		return EXIT_FAILURE;
	}

	/*
	** Preparing the program to perform scans
	*/
	start = signature();
	handling_signals();

	/*
	** For each ip found inside arguments we'll perform a scan
	*/
	size_t i = 0;
	for (; config.targets[i]; i++)
		nmap(config.targets[i], &config);

	struct timeval end;

	gettimeofday(&end, NULL);
	long seconds = (end.tv_sec - start.tv_sec);
	long micros = (((seconds * 1000000) + end.tv_usec) - (start.tv_usec)) / 1000000;
	if (i > 1)
		printf("%s done: %ld IP addresses scanned in %ld.%02ld seconds\n", prog_name, i, seconds, micros);
	else
		printf("%s done: %ld IP address scanned in %ld.%02ld seconds\n", prog_name, i, seconds, micros);

	freeiplist(config.targets);
	free(config.portrange);
	free(prog_name);
	return EXIT_SUCCESS;
}
