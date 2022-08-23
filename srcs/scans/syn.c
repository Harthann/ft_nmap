#include "ft_nmap.h"

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
					ports[i].status = STATUS_OPEN;
			}
		}
	}
	free(buffer);
	return EXIT_SUCCESS;
}


/*
** Perform a full Syn scan given a socket and a range of ports
** Will call sendto defined in send.c with the flag SYN
** Then call recv_syn to read interesting reponse only
*/
t_port_status	*scan_syn(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, uint32_t port_start, uint32_t port_end)
{
	struct scan_s		*scanlist = NULL;
	struct pollfd		fds[1];
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
	memset(fds, 0, sizeof(fds));
	fds[0].fd = sockfd;
	fds[0].events = POLLIN | POLLOUT | POLLERR;

	uint32_t i = port_start;
	while (true)
	{
		int res = poll(fds, 1, 1000);
		if (res > 0)
		{
			if (fds[0].revents & POLLIN)
				recv_syn(sockfd, scanlist, ports, nb_ports);
			else if (fds[0].revents & POLLOUT && i <= port_end)
			{
				int ret = send_tcp4(sockfd, sockaddr, iphdr, i++, &scanlist, SYN);
				if (ret == -ENOMEM)
					fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
				else if (ret == EXIT_FAILURE)
					fprintf(stderr, "%s: sendto: %s\n", prog_name, strerror(errno));
			}
			else if (i > nb_ports && fds[0].revents & POLLOUT)
				fds[0].events = POLLIN | POLLERR;
		}
		else if (!res)
			break ;
	}

//	print_scanlist(scanlist);
	return ports;
}

