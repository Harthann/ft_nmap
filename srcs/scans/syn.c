#include "ft_nmap.h"

pcap_t					*handle = NULL;

void		callback_capture(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	(void)pkthdr;
	struct scan_s		**scanlist = (void *)args;
	*scanlist = new_scanentry(*scanlist, (void *)packet + sizeof(struct sll_header));
}

void		terminate_pcap(int signum)
{
	(void)signum;
	pcap_breakloop(handle);
}

void		compute_capture(struct scan_s *scanlist, t_port_status *portrange, int nb_ports)
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

typedef struct	s_args {
	int					sockfd;
	struct sockaddr_in	sockaddr;
	struct iphdr		iphdr;
	bpf_u_int32			net;
	t_port_status		*portrange;
	uint32_t			nb_ports;
}				t_args;

void		*send_syn_packets(void *arg)
{
	t_args			*args;

	args = arg;
	send_tcp4_packets(args->sockfd, args->sockaddr, args->iphdr, args->portrange, args->nb_ports, SYN);
	free(arg);
	return (NULL);
}

/*
** Perform a full Syn scan given a socket and a range of ports
** Will call sendto defined in send.c with the flag SYN
** Then call recv_syn to read interesting reponse only
*/
t_port_status	*scan_syn(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, uint32_t *portrange, uint32_t nb_ports)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	struct scan_s		*scanlist = NULL;
	t_port_status		*ports;

	ports = calloc(nb_ports, sizeof(t_port_status));
	if (!ports)
	{
		fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
		return NULL;
	}
	for (uint32_t i = 0; i < nb_ports; i++)
	{
		ports[i].port = portrange[i];
		ports[i].flags = SET_FILTER | FILTERED;
	}
	handle = pcap_open_live("any", 1024, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "%s: pcap_open_live: %s\n", prog_name, errbuf);
		return (NULL); // TODO MORE PROBLEM
	}
	struct bpf_program	fp;
	struct in_addr		daddr = {.s_addr = iphdr->saddr};
	char				filter_exp[256];
/* Removed portrange from filter since we don't have linear range now */
	sprintf(filter_exp, "ip host %s and (tcp or icmp)", inet_ntoa(daddr));
	if (pcap_setup_filter(handle, &fp, net, (char *)filter_exp))
		return (NULL);
	pthread_t		*threadid;

	int			nb_threads = 10;
	threadid = malloc(sizeof(pthread_t) * nb_threads);
	if (!threadid) // TODO: problem + free
		return NULL;
	//int test = port_end / 2;
	int			handled_ports = 0;
	t_args *args;
	int i = 0;
	for (; i < nb_threads && handled_ports < (int)nb_ports; i++)
	{
		args = malloc(sizeof(t_args));
		if (!args)
		{
			fprintf(stderr, "%s: malloc: %s\n", prog_name, strerror(errno));
			break ;
		}
		args->sockfd = sockfd;
		args->sockaddr = *sockaddr;
		args->iphdr = *iphdr;
		args->net = net;
		args->portrange = ports + handled_ports;
		if (nb_ports / nb_threads)
			args->nb_ports = ((!i) ? (nb_ports % nb_threads) : 0) + (nb_ports / nb_threads);
		else
			args->nb_ports = 1;
		handled_ports += args->nb_ports;
		pthread_create(&threadid[i], NULL, send_syn_packets, args); // TODO: check return
	}
	nb_threads = i;
	for (;i > 0; --i)
		pthread_join(threadid[nb_threads - i], NULL); // TODO: check return
	free(threadid);
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &terminate_pcap;
	sigaction(SIGALRM, &sa, NULL);
	alarm(5);
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
	compute_capture(scanlist, ports, nb_ports);
	pcap_freecode(&fp);
	free_scanlist(scanlist);
	pcap_close(handle);
	return ports;
}
