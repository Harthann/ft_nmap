#include "ft_nmap.h"

/*
** Send multiple tcp4 packets using tcp protocol
** call to send_tcp4
*/
void		send_tcp4_packets(int sockfd, struct sockaddr_in *sockaddr,
struct iphdr *iphdr, t_port_status *portrange, int nb_ports, int flags)
{
	int					i, res, ret;
	struct pollfd		fds[1];

	memset(fds, 0, sizeof(fds));
	fds[0].fd = sockfd;
	fds[0].events = POLLOUT | POLLERR;
	i = 0;
	while (true)
	{
		res = poll(fds, 1, 1000);
		if (res > 0)
		{
			if (fds[0].revents & POLLOUT && i < nb_ports)
			{
				ret = send_tcp4(sockfd, sockaddr, iphdr, portrange[i++].port, flags);
				if (ret == -ENOMEM)
					fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
				else if (ret == EXIT_FAILURE)
					fprintf(stderr, "%s: sendto: %s\n", prog_name, strerror(errno));
			}
			else if (i >= nb_ports && fds[0].revents & POLLOUT)
				fds[0].events = POLLERR;
		}
		else if (!res)
			break ;
	}
}

/*
** Send a packet using tcp protocol
** Take a flag parameter to fill the type of tcp you send
** Flags are defined in ft_nmap
** Once send is success, the packet is added to a scanlist
*/
int			send_tcp4(int sockfd, struct sockaddr_in *sockaddr, struct iphdr *iphdr, int dst_port, uint16_t flag)
{
	void			*buffer;
	void			*data;
	struct tcphdr	*tcphdr;

	iphdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;

	buffer = calloc(iphdr->tot_len, sizeof(uint8_t));
	if (!buffer)
		return -ENOMEM;

	tcphdr = buffer + sizeof(struct iphdr);
	data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
	memcpy(buffer, iphdr, sizeof(struct iphdr));

	tcphdr = buffer + sizeof(struct iphdr);
	tcphdr->source = htons(33450);
	tcphdr->dest = htons(dst_port);
	tcphdr->syn = 1;
	SET_TCPFLAG(tcphdr, flag);
	tcphdr->window = htons(1024);
	tcphdr->doff = (uint8_t)(sizeof(struct tcphdr) / sizeof(uint32_t)); // size in 32 bit word

//	memset(data, 42, DATA_LEN);
	if (tcp4_checksum(iphdr, tcphdr, data, DATA_LEN, &tcphdr->check))
	{
		free(buffer);
		return -ENOMEM;
	}
	
	if (sendto(sockfd, buffer, iphdr->tot_len, 0, (struct sockaddr *)sockaddr, sizeof(struct sockaddr)) < 0)
	{
		free(buffer);
		return EXIT_FAILURE;

	}
	free(buffer);
	return EXIT_SUCCESS;
}


