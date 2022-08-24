#include "ft_nmap.h"

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

struct tcp4_pseudohdr {
	uint32_t		src;
	uint32_t		dst;
	uint8_t			zero;
	uint8_t			protocol;
	uint16_t		tcp_len;
};

int		tcp4_checksum(struct iphdr *iphdr, struct tcphdr *tcphdr, uint8_t *data, int data_len, uint16_t *sum)
{
	struct tcp4_pseudohdr	tcpphdr = {
		.src = iphdr->saddr,
		.dst = iphdr->daddr,
		.zero = 0,
		.protocol = IPPROTO_TCP,
		.tcp_len = htons(sizeof(struct tcphdr) + data_len)
	};
	uint8_t					*buf;

	buf = malloc(sizeof(struct tcp4_pseudohdr) + sizeof(struct tcphdr) + data_len);
	if (!buf)
		return -ENOMEM;
	memcpy(buf, &tcpphdr, sizeof(struct tcp4_pseudohdr));
	memcpy(buf + sizeof(struct tcp4_pseudohdr), tcphdr, sizeof(struct tcphdr));
	memcpy(buf + sizeof(struct tcp4_pseudohdr) + sizeof(struct tcphdr), data, data_len);
	*sum = checksum(buf, sizeof(struct tcp4_pseudohdr) + sizeof(struct tcphdr) + data_len);
	free(buf);
	return EXIT_SUCCESS;
}
