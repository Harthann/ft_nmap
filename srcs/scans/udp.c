#include "ft_nmap.h"

extern pcap_t				*handle;

/* Compute capture and handle flags */
static void		compute_capture(struct scan_s *scanlist, t_port_status *portrange, int nb_ports)
{
	struct iphdr		*iphdr;
	struct udphdr		*udphdr;
	struct icmphdr		*icmphdr;

	while (scanlist)
	{
		iphdr = scanlist->packet;
		if (iphdr->protocol == IPPROTO_UDP)
		{
			udphdr = scanlist->packet + sizeof(struct iphdr);
			for (int i = 0; i < nb_ports; i++)
			{
				if (portrange[i].port == htons(udphdr->source))
					portrange[i].flags = SET_ACCESS | OPEN;
			}
		}
		else if (iphdr->protocol == IPPROTO_ICMP)
		{
			icmphdr = scanlist->packet + sizeof(struct iphdr);
			iphdr = scanlist->packet + sizeof(struct iphdr) + sizeof(struct icmphdr);
			if (iphdr->protocol == IPPROTO_UDP)
			{
				udphdr = scanlist->packet + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr);
				for (int i = 0; i < nb_ports; i++)
				{
					if (portrange[i].port == htons(udphdr->dest))
					{
						if (icmphdr->type == 3 && icmphdr->code == 3)
							portrange[i].flags = SET_ACCESS | CLOSE;
						else
							portrange[i].flags = SET_FILTER | FILTERED;
					}
				}
			}
		}
		scanlist = scanlist->next;
	}
}

t_port_status	*scan_udp(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, scanconf_t *config)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	struct scan_s		*scanlist = NULL;
	t_port_status		*ports;
	char				filter_exp[256];
	struct bpf_program	fp;
	struct in_addr		daddr = {.s_addr = iphdr->saddr};

	ports = calloc(config->nb_ports, sizeof(t_port_status));
	if (!ports)
	{
		fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
		return NULL;
	}
	/* INIT PORTS FOR FLAGS FOR XMAS SCAN */
	for (uint32_t i = 0; i < config->nb_ports; i++)
	{
		ports[i].port = config->portrange[i];
		ports[i].flags = SET_ACCESS | OPEN | SET_FILTER | FILTERED;
	}
	handle = pcap_open_live("any", 1024, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "%s: pcap_open_live: %s\n", prog_name, errbuf);
		free(ports);
		return (NULL);
	}
	/* Removed portrange from filter since we don't have linear range now */
	sprintf(filter_exp, "ip host %s and (udp or icmp)", inet_ntoa(daddr));
	if (pcap_setup_filter(handle, &fp, net, (char *)filter_exp))
	{
		pcap_close(handle);
		free(ports);
		return (NULL);
	}
	if (thread_send(sockfd, sockaddr, iphdr, 0, config, ports, send_udp4_packets, config->nb_threads))
	{
		pcap_freecode(&fp);
		pcap_close(handle);
		free(ports);
		return (NULL);
	}
	/* SETUP PCAP EXIT IN SECONDS */
	setup_pcap_exit(config->timeout);
	while (true)
	{
		int ret = pcap_dispatch(handle, -1, callback_capture, (void *)&scanlist);
		if (ret == PCAP_ERROR) {
			fprintf(stderr, "%s: pcap_dispatch: error\n", prog_name);
			break ;
		}
		else if (ret == PCAP_ERROR_BREAK)
			break ;
	}
	compute_capture(scanlist, ports, config->nb_ports);
	pcap_freecode(&fp);
	free_scanlist(scanlist);
	pcap_close(handle);
	return ports;
}
