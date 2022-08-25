#include "ft_nmap.h"

int		init_socket(char *target, sockfd_t *socks)
{
	char			*target_ip;
	uint32_t		dst_addr;
	int on = 1;

	target_ip = resolve_hostname(target);
	if (!target_ip) {
		fprintf(stderr, "%s: Failed to resolve \"%s\".\n", prog_name, target);
		return EXIT_FAILURE;
	}
	inet_pton(AF_INET, target_ip, &dst_addr);

	socks->sockfd_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (socks->sockfd_tcp < 0) {
		fprintf(stderr, "%s: socket: %s\n", prog_name, strerror(errno));
		free(target_ip);
		return EXIT_FAILURE;
	}

//	dev_name = get_device();
//	if (!dev_name) {
//		free(target_ip);
//		return EXIT_FAILURE;
//	}

	setsockopt(socks.sockfd_tcp, IPPROTO_IP, IP_HDRINCL, &(const char){1}, sizeof(char));

	struct sockaddr_in sockaddr;
	sockaddr.sin_addr.s_addr = dst_addr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = 0;
	
	return EXIT_SUCCESS;

//	struct iphdr	iphdr = {
//		.version = 4,
//		.ihl = sizeof(struct iphdr) / sizeof(uint32_t),
//		.tos = 0,
//		.tot_len = 0,
//		.id = 0,
//		.frag_off = 0,
//		.ttl = 255,
//		.protocol = IPPROTO_TCP,
//		.check = 0, // filled by kernel
//		.saddr = 0,
//		.daddr = dst_addr
//	};
//
//	if (get_ipv4_addr((int *)&iphdr.saddr, dev_name) == EXIT_FAILURE) {
//		free(dev_name);
//		free(target_ip);
//		return EXIT_FAILURE;
//	}
}

