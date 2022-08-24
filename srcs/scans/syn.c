#include "ft_nmap.h"

pcap_t				*handle = NULL;
struct scan_s		*scanlist = NULL;

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
	printf("IPv%d:{\nId:%d\nSaddr: %s\nDaddr: %s\n}\n", ntohs(ip->version), ip->id, inet_ntoa(saddr), inet_ntoa(daddr));
	scanlist = new_scanentry(scanlist, (void *)packet + sizeof(struct sll_header));
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
** Wrap the recvfrom function in order to retreive only response to our syn request
** Response type:
**			Syn/Ack: Port open
**			Rst/Ack: Port close
**			No response: Filtered
*/
int			recv_syn(int sockfd, struct scan_s *scanlist, t_port_status *ports, int nb_port)
{
	void					*buffer;
	int						len;
	struct tcphdr			*tcphdr;
//	struct iphdr			*iphdr_rcv;

	len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;
	buffer = malloc(len);
	if (!buffer)
		return -ENOMEM;

	if (recvfrom(sockfd, buffer, len, 0, NULL, NULL) < 0)
	{
		free(buffer);
		fprintf(stderr, "recvfrom: %s\n", strerror(errno));
		free(buffer);
		return EXIT_FAILURE;
	}

//	iphdr_rcv = buffer;

/*
** Perform a check if the response correspond to one of our scan
** If so check the responses flag and print scan result
*/
	tcphdr = buffer + sizeof(struct iphdr);
	if (find_scan(buffer, scanlist)) {
		if (TCP_FLAG(tcphdr) == (SYN | ACK))
		{
			for (int i = 0; i < nb_port; i++)
			{
				if (ports[i].port == htons(tcphdr->source))
					ports[i].flags = OPEN;
			}
		}
	}
	free(buffer);
	return EXIT_SUCCESS;
}

void			start_capture(int sockfd, struct sockaddr_in *sockaddr,  struct iphdr *iphdr, bpf_u_int32 net, int port_start, int port_end) // THREAD ?
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live("any", 1024, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "%s: pcap_open_live: %s\n", prog_name, errbuf);
		return ;
	}
	struct pollfd		fds[1];
	int		nb_ports;

	nb_ports = (port_end - port_start) + 1;
	memset(fds, 0, sizeof(fds));
	fds[0].fd = sockfd;
	fds[0].events = POLLOUT | POLLERR;

	int i = port_start;
	while (true)
	{
		int res = poll(fds, 1, 1000);
		if (res > 0)
		{
			if (fds[0].revents & POLLOUT && i <= port_end)
			{
				int ret = send_tcp4(sockfd, sockaddr, iphdr, i++, SYN);
				if (ret == -ENOMEM)
					fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
				else if (ret == EXIT_FAILURE)
					fprintf(stderr, "%s: sendto: %s\n", prog_name, strerror(errno));
			}
			else if (i > nb_ports && fds[0].revents & POLLOUT)
				fds[0].events = POLLERR;
		}
		else if (!res)
			break ;
	}
	struct bpf_program fp;
	struct in_addr daddr = {.s_addr = iphdr->saddr};
	char filter_exp[256];
	sprintf(filter_exp, "ip host %s and (tcp  and portrange %d-%d or icmp)", inet_ntoa(daddr), port_start, port_end);
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_compile: %s: %s\n", prog_name, filter_exp, pcap_geterr(handle));
		return ; // TODO: free ?
	}
	if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_setfilter: %s: %s\n", prog_name, filter_exp, pcap_geterr(handle));
		return ; // TODO: free ?
	}

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
	pcap_freecode(&fp);
}

/*
** Perform a full Syn scan given a socket and a range of ports
** Will call sendto defined in send.c with the flag SYN
** Then call recv_syn to read interesting reponse only
*/
t_port_status	*scan_syn(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, uint32_t port_start, uint32_t port_end)
{
	uint32_t			nb_ports;
	t_port_status		*ports;

	nb_ports = (port_end - port_start) + 1;
	ports = calloc(nb_ports, sizeof(t_port_status));
	if (!ports)
	{
		fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
		return NULL;
	}
	for (uint32_t i = 0; i < port_end - port_start - 1; i++)
		ports[i].port = port_start + i;
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &terminate_pcap;
	sigaction(SIGALRM, &sa, NULL);
	alarm(5);
	// TODO: pthread here ?
	start_capture(sockfd, sockaddr, iphdr, net, port_start, port_end);
	struct scan_s *tmp;

	tmp = scanlist;
	while (tmp)
	{
		struct iphdr		*iphdr;
		struct tcphdr		*tcphdr;

		iphdr = tmp->packet;
		if (iphdr->protocol == IPPROTO_TCP)
		{
			tcphdr = tmp->packet + sizeof(struct iphdr);
			if (TCP_FLAG(tcphdr) == (SYN | ACK))
			{
				for (uint32_t i = 0; i < nb_ports; i++)
				{
					if (ports[i].port == htons(tcphdr->source))
						ports[i].flags = SET_ACCESS | OPEN;
				}
			}
		}
		tmp = tmp->next;
	}
	free_scanlist(scanlist);
	pcap_close(handle);
	return ports;
}
