#include "ft_nmap.h"
#include "args.h"

char f_flood = 0;
char *prog_name = NULL;

unsigned short checksum(void *addr, size_t count)
{
	unsigned short *ptr;
	unsigned long sum;

	ptr = addr;
	for (sum = 0; count > 1; count -= 2)
		sum += *ptr++;
	if (count > 0)
		sum += *(unsigned char *)ptr;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (~sum);
}

struct tcp_pseudohdr {
	uint32_t		src;
	uint32_t		dst;
	uint8_t			zero;
	uint8_t			protocol;
	uint16_t		tcp_len;
	struct tcphdr	tcphdr;
};

uint16_t	tcp4_checksum(uint32_t src, uint32_t dst, struct tcphdr *tcphdr, uint8_t *data, int data_size)
{
	uint8_t					buff[sizeof(struct tcp_pseudohdr) + data_size];
	struct tcp_pseudohdr	*tcpphdr;

	tcpphdr = (void *)buff;
	memset(buff, 0, sizeof(buff));
	memcpy(&tcpphdr->tcphdr, tcphdr, sizeof(struct tcphdr));
	memcpy(buff + sizeof(struct tcp_pseudohdr), data, data_size);
	tcpphdr->src = src;
	tcpphdr->dst = dst;
	tcpphdr->protocol = IPPROTO_TCP;
	tcpphdr->tcp_len = sizeof(struct tcphdr) + data_size;
	return (checksum(buff, sizeof(buff)));
}

int			poc_tcp()
{
	sockfd_t			socks;

	socks.sockfd_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (socks.sockfd_tcp < 0)
	{
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		return EXIT_FAILURE;
	}
	/* struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
	} */
	uint32_t	src_addr;
	uint32_t	dst_addr;

	inet_pton(AF_INET, "192.168.175.128", &src_addr);
	inet_pton(AF_INET, "192.168.175.1", &dst_addr);
	struct sockaddr_in sockaddr;
	sockaddr.sin_addr.s_addr = dst_addr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = 0;
	void				*buf;
	int					len = sizeof(struct iphdr) + sizeof(struct tcphdr) + 8;

	buf = malloc(len);
	struct iphdr		*iphdr = buf;
	struct tcphdr		*tcphdr = buf + sizeof(struct iphdr);

	memset(iphdr, 0, sizeof(struct iphdr));
	iphdr->version = 4; // ipv4
	iphdr->ihl = sizeof(struct iphdr) / 4; // 5 = 20 / 32 bits
	iphdr->tos = 0;
	iphdr->tot_len = len;
	iphdr->id = 0;
	iphdr->frag_off = 0;
	iphdr->ttl = 111;
	iphdr->protocol = IPPROTO_TCP;
	iphdr->check = 0; // filled by kernel
	iphdr->saddr = INADDR_ANY;
	iphdr->daddr = dst_addr;
	memset(tcphdr, 0, sizeof(struct tcphdr));
	tcphdr->source = htons(22);
	tcphdr->dest = htons(33450);
	tcphdr->syn = 1;
	tcphdr->window = 1024;
	memset(buf + sizeof(struct tcphdr) + sizeof(struct iphdr), 42, 8);
	tcphdr->check = tcp4_checksum(src_addr, dst_addr, tcphdr, buf + sizeof(struct tcphdr) + sizeof(struct iphdr), 8);
	if (sendto(socks.sockfd_tcp, buf, len, 0, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr)) < 0)
	{
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int			nmap(void)
{
	struct tm		*info;
	struct timeval	tv;
	time_t			t;

	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
	info = localtime(&t);
	printf("Starting %s %s at %d-%02d-%02d %02d:%02d EDT\n", PROG_NAME, VERSION,
info->tm_year + 1900, info->tm_mon + 1, info->tm_mday, info->tm_hour, info->tm_min);
	poc_tcp();
	return EXIT_SUCCESS;
}

int			main(int ac, char **av)
{
	int		ret;

	prog_name = strdup((*av[0]) ? av[0] : PROG_NAME);
	if (!prog_name)
	{
		fprintf(stderr, "%s: %s\n", PROG_NAME, strerror(errno));
		return EXIT_FAILURE;
	}
	if (parse_arg(ac - 1, av + 1) != 0)
	{
		free(prog_name);
		return EXIT_FAILURE;
	}
	ret = nmap();
	free(prog_name);
	return ret;
}
