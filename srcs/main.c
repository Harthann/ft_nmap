#include "ft_nmap.h"
#include "args.h"

char *prog_name = NULL;
pcap_t	*handle = NULL;

void dbg_dump_bytes(const void* data, size_t size) {
	char ascii[17];
	size_t i;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		if (i % 16 == 0)
			fprintf(stderr, "%p: ", data + i);
		fprintf(stderr, "%02x ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			fprintf(stderr, " ");
			if ((i+1) % 16 == 0) {
				fprintf(stderr, "|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					fprintf(stderr, " ");
				}
				fprintf(stderr, "%*.0d", 3 * (16 - (((int)i + 1) % 16)), 0);
				fprintf(stderr, "|  %s \n", ascii);
			}
		}
	}
}

#include <linux/if_ether.h>
#include <pcap/sll.h>
void		my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{
	(void)args;
	(void)pkthdr;
	(void)packet;
	static int count = 1;
	struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct sll_header));

	struct in_addr saddr = {.s_addr = ip->saddr};
	struct in_addr daddr = {.s_addr = ip->daddr};
	printf("Sizeof eth hdr: %ld\n", sizeof(struct sll_header));
	dbg_dump_bytes(ip, sizeof(struct iphdr));
	printf("IPv%d:{\nId:%d\nSaddr: %s\nDaddr: %s\n}\n", ntohs(ip->version), ip->id, inet_ntoa(saddr), inet_ntoa(daddr));
	//fprintf(stdout, "%3d, ", count);
	//fflush(stdout);
	count++;
}

void		terminate_pcap(int signum)
{
	(void)signum;
	pcap_breakloop(handle);
}

/*
** Target is a string containing either the ip or the domain name of the target
** Ports[0] correspond to the first port to scan and ports[1] the last
** Performuing ports[1] - ports[0] should give the number of ports
** This number should lend between 1 and 1024
*/
void		nmap(char *target, int portrange[2])
{
	char			*dev_name;
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
	dev_name = get_device();
	if (!dev_name)
	{
		free(target_ip);
		return ;
	}
	int on = 1;
	setsockopt(socks.sockfd_tcp, IPPROTO_IP, IP_HDRINCL, (const char *)&on, sizeof(on));
// ===
// ===
	struct sockaddr_in sockaddr;
	sockaddr.sin_addr.s_addr = dst_addr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = 0;
	(void)portrange;
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
	if (get_ipv4_addr((int *)&iphdr.saddr, dev_name) == EXIT_FAILURE)
	{
		free(dev_name);
		free(target_ip);
		return ;
	}
	char	errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (pcap_lookupnet(dev_name, &net, &mask, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_loopkupnet: %s\n", prog_name, errbuf);
		net = 0;
		mask = 0;

	}

	handle = pcap_open_live("any", 1024, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "%s: pcap_open_live: %s\n", prog_name, errbuf);
		free(dev_name);
		free(target_ip);
		return ;
	}

	struct bpf_program fp;
	char filter_exp[] = "port 22";
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_compile: %s: %s\n", prog_name, filter_exp, pcap_geterr(handle));
		return ;
	}
	if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_setfilter: %s: %s\n", prog_name, filter_exp, pcap_geterr(handle));
		return ;
	}
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &terminate_pcap;
	sigaction(SIGALRM, &sa, NULL);
	alarm(10);

	t_port_status *ports = scan_syn(socks.sockfd_tcp, &sockaddr, &iphdr, portrange[0], portrange[1]);
	(void)ports;

	while (1) {
		int ret = pcap_dispatch(handle, -1, my_callback, NULL);
		if (ret == PCAP_ERROR) {
			printf("error\n");
			break ;
		}
		else if (ret == PCAP_ERROR_BREAK) {
			printf("error break\n");
			break ;
		}
		else {
			printf("all fine\n");
		}
	}
	pcap_close(handle);
	/*
	t_port_status *ports = scan_syn(socks.sockfd_tcp, &sockaddr, &iphdr, portrange[0], portrange[1]);
	if (!ports)
	{
		free(dev_name);
		free(target_ip);
		return ;
	}
	printf("%s scan report for %s (%s)\n", prog_name, target, target_ip);
	printf("PORT      STATUS            SERVICE\n");
	for (uint32_t i = 0; i < ((uint32_t)portrange[1] - portrange[0] + 1); i++)
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
	*/
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
