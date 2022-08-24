#include "ft_nmap.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
struct pcap_t_handlers	*handlers = NULL;
struct scan_s			*scanlist = NULL;
void		my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	(void)args;
	(void)pkthdr;
//	struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct sll_header));

//	struct in_addr saddr = {.s_addr = ip->saddr};
//	struct in_addr daddr = {.s_addr = ip->daddr};
//	printf("Sizeof eth hdr: %ld\n", sizeof(struct sll_header));
//	printf("IPv%d:{\nId:%d\nSaddr: %s\nDaddr: %s\n}\n", ntohs(ip->version), ip->id, inet_ntoa(saddr), inet_ntoa(daddr));
	// TODO: error and mutex
	pthread_mutex_lock(&mutex);
	scanlist = new_scanentry(scanlist, (void *)packet + sizeof(struct sll_header));
	pthread_mutex_unlock(&mutex);
}

void		terminate_pcap(int signum)
{
	struct pcap_t_handlers *tmp;

	(void)signum;
	tmp = handlers;
	while (tmp)
	{
		pcap_breakloop(tmp->handle);
		tmp = tmp->next;
	}
}

/*
** Wrap the recvfrom function in order to retreive only response to our syn request
** Response type:
**			Syn/Ack: Port open
**			Rst/Ack: Port close
**			No response: Filtered
*/
//int			recv_syn(int sockfd, struct scan_s *scanlist, t_port_status *ports, int nb_port)
//{
//	void					*buffer;
//	int						len;
//	struct tcphdr			*tcphdr;
////	struct iphdr			*iphdr_rcv;
//
//	len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;
//	buffer = malloc(len);
//	if (!buffer)
//		return -ENOMEM;
//
//	if (recvfrom(sockfd, buffer, len, 0, NULL, NULL) < 0)
//	{
//		free(buffer);
//		fprintf(stderr, "recvfrom: %s\n", strerror(errno));
//		free(buffer);
//		return EXIT_FAILURE;
//	}
//
////	iphdr_rcv = buffer;
//
///*
//** Perform a check if the response correspond to one of our scan
//** If so check the responses flag and print scan result
//*/
//	tcphdr = buffer + sizeof(struct iphdr);
//	if (find_scan(buffer, scanlist)) {
//		if (TCP_FLAG(tcphdr) == (SYN | ACK))
//		{
//			for (uint32_t i = 0; i < nb_port; i++)
//			{
//				if (ports[i].port == htons(tcphdr->source))
//					ports[i].flags = OPEN;
//			}
//		}
//	}
//	free(buffer);
//	return EXIT_SUCCESS;
//}

typedef struct	s_args {
	int					sockfd;
	struct sockaddr_in	*sockaddr;
	struct iphdr		*iphdr;
	bpf_u_int32			net;
	uint32_t			*portrange;
	uint32_t			nb_ports;
}				t_args;

void		*start_capture(void *arg) // THREAD ?
{
	t_args *args = arg;
	pcap_t		*handle;

	char	errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live("any", 1024, 1, 1000, errbuf);
	if (!handle)
	{
		fprintf(stderr, "%s: pcap_open_live: %s\n", prog_name, errbuf);
		free(args);
		return (NULL);
	}
	// TODO: mutex and error on new_handlerentry
	pthread_mutex_lock(&mutex);
	handlers = new_handlerentry(handlers, handle);
	pthread_mutex_unlock(&mutex);
	if (!handlers)
	{
		// TODO: problem !
	}
	struct pollfd		fds[1];
	//int		nb_ports;

	//nb_ports = (args->port_end - args->port_start) + 1;
	memset(fds, 0, sizeof(fds));
	fds[0].fd = args->sockfd;
	fds[0].events = POLLOUT | POLLERR;

	uint32_t i = 0;
	while (true)
	{
		int res = poll(fds, 1, 1000);
		if (res > 0)
		{
			if (fds[0].revents & POLLOUT && i <= args->nb_ports)
			{
				int ret = send_tcp4(args->sockfd, args->sockaddr, args->iphdr, args->portrange[i++], SYN);
				if (ret == -ENOMEM)
					fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
				else if (ret == EXIT_FAILURE)
					fprintf(stderr, "%s: sendto: %s\n", prog_name, strerror(errno));
			}
			else if (i > args->nb_ports && fds[0].revents & POLLOUT)
				fds[0].events = POLLERR;
		}
		else if (!res)
			break ;
	}
	struct bpf_program fp;
	struct in_addr daddr = {.s_addr = args->iphdr->saddr};
	char filter_exp[256];
/* Removed portrange from filter since we don't have linear range now */
	sprintf(filter_exp, "ip host %s and (tcp or icmp)", inet_ntoa(daddr));
	if (pcap_compile(handle, &fp, filter_exp, 0, args->net) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_compile: %s: %s\n", prog_name, filter_exp, pcap_geterr(handle));
		pcap_freecode(&fp);
		free(args);
		return (NULL); // TODO: free ?
	}
	if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
		fprintf(stderr, "%s: pcap_setfilter: %s: %s\n", prog_name, filter_exp, pcap_geterr(handle));
		pcap_freecode(&fp);
		free(args);
		return (NULL); // TODO: free ?
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
	free(args);
	return (NULL);
}

/*
** Perform a full Syn scan given a socket and a range of ports
** Will call sendto defined in send.c with the flag SYN
** Then call recv_syn to read interesting reponse only
*/
t_port_status	*scan_syn(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, bpf_u_int32 net, uint32_t *portrange, uint32_t nb_ports)
{
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
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &terminate_pcap;
	sigaction(SIGALRM, &sa, NULL);
	alarm(5);

	if (pthread_mutex_init(&mutex, NULL))
	{
		//TODO: problem
	}
	pthread_t		threadid[2];
	//int test = port_end / 2;
	t_args *args;
	for (int i = 0; i < 2; i++)
	{
		args = malloc(sizeof(t_args));
		args->sockfd = sockfd;
		args->sockaddr = sockaddr;
		args->iphdr = iphdr;
		args->net = net;
		args->portrange = portrange + (i * nb_ports / 2);
		args->nb_ports = nb_ports / 2;
	//	start_capture(&args);
		pthread_create(&threadid[i], NULL, start_capture, args); // TODO: check return
		//port_start = test + 1;
		//test *= 2;
	}
	for (int i = 0; i < 2; i++)
		pthread_join(threadid[i], NULL); // TODO: check return
	if (pthread_mutex_destroy(&mutex))
	{
		//TODO: problem
	}
	struct scan_s *tmp;

	tmp = scanlist;
	int count = 0;
	for (struct scan_s *tmp2 = tmp; tmp2; tmp2 = tmp2->next)
		count++;
	printf("%d\n", count);
	while (tmp)
	{
		struct iphdr		*iphdr;
		struct tcphdr		*tcphdr;

		iphdr = tmp->packet;
		if (iphdr->protocol == IPPROTO_TCP)
		{
			tcphdr = tmp->packet + sizeof(struct iphdr);
			printf("TCP:{%d %d}\n", htons(tcphdr->source), TCP_FLAG(tcphdr));
			for (uint32_t i = 0; i < nb_ports; i++)
			{
				if (ports[i].port == htons(tcphdr->source))
				{
					if (TCP_FLAG(tcphdr) == (SYN | ACK))
						ports[i].flags = SET_ACCESS | OPEN;
					else
						ports[i].flags = SET_ACCESS | CLOSE;
				}
			}
		}
		tmp = tmp->next;
	}
	free_scanlist(scanlist);
	free_handlers(handlers);
	return ports;
}
