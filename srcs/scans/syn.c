#include "ft_nmap.h"

pcap_t					*handle = NULL;

void		callback_capture(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	(void)pkthdr;
	struct scan_s		**scanlist = (void *)args;
	*scanlist = new_scanentry(*scanlist, (void *)packet + sizeof(struct sll_header));
}

/* Compute capture and handle flags */
static void		compute_capture(struct scan_s *scanlist, t_port_status *portrange, int nb_ports)
{
	struct iphdr		*iphdr;
	struct tcphdr		*tcphdr;

	while (scanlist)
	{
		iphdr = scanlist->packet;
		if (iphdr->protocol == IPPROTO_TCP)
		{
			tcphdr = scanlist->packet + sizeof(struct iphdr);
			for (int i = 0; i < nb_ports; i++)
			{
				if (portrange[i].port == htons(tcphdr->source))
				{
					if (TCP_FLAG(tcphdr) == (SYN | ACK))
						portrange[i].flags = SET_ACCESS | OPEN;
					else
						portrange[i].flags = SET_ACCESS | CLOSE;
				}
			}
		}
		scanlist = scanlist->next;
	}
}

/*
** Perform a full Syn scan given a socket and a range of ports
** Will call sendto defined in send.c with the flag SYN
** Then call recv_syn to read interesting reponse only
*/
t_port_status	*scan_syn(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, scanconf_t *config)
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
	/* INIT PORTS FOR FLAGS FOR SYN SCAN */
	for (uint32_t i = 0; i < config->nb_ports; i++)
	{
		ports[i].port = config->portrange[i];
		ports[i].flags = SET_FILTER | FILTERED;
	}
	handle = pcap_open_live("any", 1024, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "%s: pcap_open_live: %s\n", prog_name, errbuf);
		free(ports);
		return (NULL);
	}
	/* Removed portrange from filter since we don't have linear range now */
	sprintf(filter_exp, "ip host %s and (tcp or icmp)", inet_ntoa(daddr));
	if (pcap_setup_filter(handle, &fp, net, (char *)filter_exp))
	{
		pcap_close(handle);
		free(ports);
		return (NULL);
	}
	if (thread_send(sockfd, sockaddr, iphdr, SYN, config, ports, send_tcp4_packets, config->nb_threads))
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
