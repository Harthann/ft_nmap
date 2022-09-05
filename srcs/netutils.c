#include "ft_nmap.h"

/*
** Use of libpcap to get network interface available
** Use of gcc diagnostic ignore to ignore deprecated warning
** This is done cause of pcap_lookupdev being deprecated
** And the project has to use it since it's ask in subject
*/
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
char		*get_device(void)
{
	char			*name, *tmp;
	char			errbuf[PCAP_ERRBUF_SIZE];

	if (!(tmp = pcap_lookupdev(errbuf))) {
		fprintf(stderr, "%s: pcap_lookupdev: %s\n", prog_name, errbuf);
		return NULL;
	}
	if (!(name = strdup(tmp))) {
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
	if (getifaddrs(&ifap)) {
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
	struct hostent	*hostent;
	char			*addr;
	struct in_addr **addr_list;

	addr = NULL;
	if ((hostent = gethostbyname(hostname))) {
		addr_list = (struct in_addr **)hostent->h_addr_list;
		if (hostent->h_addrtype == AF_INET6 || !addr_list || !(*addr_list))
			return NULL;
		addr = malloc(MAX_ADDR_SIZE);
		if (!addr)
			return NULL;
		inet_ntop(AF_INET, *addr_list, addr, INET_ADDRSTRLEN);
	}
	return addr;
}

/*
** Initialize socket to send tcp packet
*/
int		init_socket(int *fd, int proto)
{

	*fd = socket(AF_INET, SOCK_RAW, proto);
	if (*fd < 0) {
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		return EXIT_FAILURE;
	}

	if (setsockopt(*fd, IPPROTO_IP, IP_HDRINCL, &(const char){1}, sizeof(char)) < 0) {
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}


