#include "ft_nmap.h"

/*
** Use of libpcap to get network interface available
*/
char		*get_device(void)
{
	char			*name;
	pcap_if_t		*alldesvp, *tmp;
	char			errbuf[PCAP_ERRBUF_SIZE];
	name = NULL;
	if (pcap_findalldevs(&alldesvp, errbuf) == PCAP_ERROR)
	{
		fprintf(stderr, "%s: pcap_findalldevs: %s\n", prog_name, errbuf);
		return NULL;
	}
	tmp = alldesvp;
	while (tmp)
	{
		if (!(tmp->flags & PCAP_IF_LOOPBACK) && (tmp->flags & PCAP_IF_UP) &&
(tmp->flags & PCAP_IF_RUNNING) &&
(tmp->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_CONNECTED)
			break ;
		tmp = tmp->next;
	}
	if (tmp && !(name = strdup(tmp->name)))
		fprintf(stderr, "%s: strdup: %s\n", prog_name, strerror(errno));
	pcap_freealldevs(alldesvp);
	return name;
}

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


