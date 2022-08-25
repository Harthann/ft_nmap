#include "ft_nmap.h"

/*
** Use of libpcap to get network interface available
*/
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

char		*get_device(void)
{
	char			*name, *tmp;
	char			errbuf[PCAP_ERRBUF_SIZE];

	if (!(tmp = pcap_lookupdev(errbuf)))
	{
		fprintf(stderr, "%s: pcap_lookupdev: %s\n", prog_name, errbuf);
		return NULL;
	}
	if (!(name = strdup(tmp)))
	{
		fprintf(stderr, "%s: strdup: %s\n", prog_name, strerror(errno));
		return NULL;
	}
	return name;
}
#pragma GCC diagnostic pop

/*
** Use of getifaddr to get our own ip address
** This is needed to fill ipv4 header
*/
int			get_ipv4_addr(int *addr, char *name)
{
	int					ret;
	struct ifaddrs		*ifap, *tmp;
	struct sockaddr_in	*paddr;

	ret = EXIT_FAILURE;
	if (getifaddrs(&ifap))
	{
		fprintf(stderr, "%s: getifaddrs: %s\n", prog_name, strerror(errno));
		return EXIT_FAILURE;
	}
	tmp = ifap;
	while (tmp)
	{
		if (tmp->ifa_name && tmp->ifa_addr->sa_family == AF_INET && !strcmp(name, tmp->ifa_name))
		{
			printf("Suitable device '%s' found.\n", name);
			paddr = (struct sockaddr_in *)tmp->ifa_addr;
			inet_pton(AF_INET, inet_ntoa(paddr->sin_addr), addr);
			ret = EXIT_SUCCESS;
		}
		tmp = tmp->ifa_next;
	}
	if (ret == EXIT_FAILURE)
		fprintf(stderr, "No suitable device found.\n");
	freeifaddrs(ifap);
	return (ret);
}

/*
** Resolve hostname received and return a struct addrinfo
** This allow us to contruct a socket base on the result
** Or return an error if the ip/hostname is invalid
*/
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

int		init_socket(char *target, sockfd_t *socks, char **target_ip, uint32_t *dst_addr)
{
	int				fd;

	*target_ip = resolve_hostname(target);
	if (!*target_ip) {
		fprintf(stderr, "%s: Failed to resolve \"%s\".\n", prog_name, target);
		return EXIT_FAILURE;
	}
	inet_pton(AF_INET, *target_ip, dst_addr);

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (fd < 0) {
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		free(*target_ip);
		return EXIT_FAILURE;
	}

	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &(const char){1}, sizeof(char));

//	struct sockaddr_in sockaddr;
//	sockaddr.sin_addr.s_addr = *dst_addr;
//	sockaddr.sin_family = AF_INET;
//	sockaddr.sin_port = 0;
	
	socks->sockfd_tcp = fd;
	return EXIT_SUCCESS;

//	struct iphdr	iphdr = {
//		.version = 4,
//		.ihl = sizeof(struct iphdr) / sizeof(uint32_t),
//		.tos = 0,
//		.tot_len = 0,
//		.id = 0,
//		.frag_off = 0,
//		.ttl = 255,
//		.protocol = IPPROTO_TCP,
//		.check = 0, // filled by kernel
//		.saddr = 0,
//		.daddr = dst_addr
//	};
//
//	if (get_ipv4_addr((int *)&iphdr.saddr, dev_name) == EXIT_FAILURE) {
//		free(dev_name);
//		free(target_ip);
//		return EXIT_FAILURE;
//	}
}

