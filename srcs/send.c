#include "ft_nmap.h"

int				thread_send(int sockfd, struct sockaddr_in * sockaddr, struct iphdr *iphdr, int flags, scanconf_t *config, t_port_status *ports, void *(fn(void *)), int nb_threads)
{
	pthread_t		*threadid;

	threadid = malloc(sizeof(pthread_t) * nb_threads);
	if (!threadid) // TODO: problem + free
	{
		fprintf(stderr, "%s: malloc: %s\n", prog_name, strerror(errno));
		return EXIT_FAILURE;
	}
	//int test = port_end / 2;
	int			handled_ports = 0;
	t_args_send *args;
	int i = 0;
	for (; i < nb_threads && handled_ports < (int)config->nb_ports; i++)
	{
		args = malloc(sizeof(t_args_send));
		if (!args)
		{
			fprintf(stderr, "%s: malloc: %s\n", prog_name, strerror(errno));
			break ;
		}
		args->sockfd = sockfd;
		args->sockaddr = *sockaddr;
		args->iphdr = *iphdr;
		args->portrange = ports + handled_ports;
		if (config->nb_ports / nb_threads)
			args->nb_ports = ((!i) ? (config->nb_ports % nb_threads) : 0) + (config->nb_ports / nb_threads);
		else
			args->nb_ports = 1;
		args->flags = flags;
		handled_ports += args->nb_ports;
		pthread_create(&threadid[i], NULL, fn, args); // TODO: check return
	}
	nb_threads = i;
	for (;i > 0; --i)
		pthread_join(threadid[nb_threads - i], NULL); // TODO: check return
	free(threadid);
	return EXIT_SUCCESS;
}

/*
** Send multiple tcp4 packets using tcp protocol
** call to send_tcp4
*/
void		*send_tcp4_packets(void *args)
{
	t_args_send			*send;
	int					i, res, ret;
	struct pollfd		fds[1];

	send = args;
	memset(fds, 0, sizeof(fds));
	fds[0].fd = send->sockfd;
	fds[0].events = POLLOUT | POLLERR;
	i = 0;
	while (true)
	{
		res = poll(fds, 1, 1000);
		if (res > 0)
		{
			if (fds[0].revents & POLLOUT && i < send->nb_ports)
			{
				ret = send_tcp4(send->sockfd, send->sockaddr, send->iphdr, send->portrange[i++].port, send->flags);
				if (ret == -ENOMEM)
					fprintf(stderr, "%s: calloc: %s\n", prog_name, strerror(errno));
				else if (ret == EXIT_FAILURE)
					fprintf(stderr, "%s: sendto: %s\n", prog_name, strerror(errno));
			}
			else if (i >= send->nb_ports && fds[0].revents & POLLOUT)
				fds[0].events = POLLERR;
		}
		else if (!res)
			break ;
	}
	free(send);
	return (NULL);
}

/*
** Send a packet using tcp protocol
** Take a flag parameter to fill the type of tcp you send
** Flags are defined in ft_nmap
** Once send is success, the packet is added to a scanlist
*/
int			send_tcp4(int sockfd, struct sockaddr_in sockaddr, struct iphdr iphdr, int dst_port, uint16_t flag)
{
	void			*buffer;
	void			*data;
	struct tcphdr	*tcphdr;

	iphdr.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + DATA_LEN;

	buffer = calloc(iphdr.tot_len, sizeof(uint8_t));
	if (!buffer)
		return -ENOMEM;

	tcphdr = buffer + sizeof(struct iphdr);
	data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
	memcpy(buffer, &iphdr, sizeof(struct iphdr));

	tcphdr = buffer + sizeof(struct iphdr);
	tcphdr->source = htons(33450);
	tcphdr->dest = htons(dst_port);
	tcphdr->syn = 1;
	SET_TCPFLAG(tcphdr, flag);
	tcphdr->window = htons(1024);
	tcphdr->doff = (uint8_t)(sizeof(struct tcphdr) / sizeof(uint32_t)); // size in 32 bit word

//	memset(data, 42, DATA_LEN);
	if (tcp4_checksum(&iphdr, tcphdr, data, DATA_LEN, &tcphdr->check))
	{
		free(buffer);
		return -ENOMEM;
	}
	
	if (sendto(sockfd, buffer, iphdr.tot_len, 0, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr)) < 0)
	{
		free(buffer);
		return EXIT_FAILURE;

	}
	free(buffer);
	return EXIT_SUCCESS;
}


