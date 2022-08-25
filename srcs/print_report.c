#include "ft_nmap.h"

void	print_report(t_port_status *ports, uint32_t nb_ports, char *target, char *target_ip)
{
	printf("%s scan report for %s (%s)\n", prog_name, target, target_ip);
	printf("PORT      STATUS            SERVICE\n");

	for (uint32_t i = 0; i < nb_ports; i++)
	{
		if (ports[i].flags & SET_ACCESS || ports[i].flags & SET_FILTER) {
			int		n;
			struct servent* servi = getservbyport(htons(ports[i].port), "tcp");
			printf("%d/tcp%n", ports[i].port, &n);
			printf("%*c", 10 - n, ' ');
			int		m = 0;
			if (ports[i].flags & SET_ACCESS) {
				if (ports[i].flags & OPEN) printf("open%n", &n);
				else
					printf("close%n", &n);
			}
			if (ports[i].flags & SET_FILTER) {
				if (ports[i].flags & SET_ACCESS) {
					printf("|");
					n++;
				}
				if (ports[i].flags & FILTERED)
					printf("filtered%n", &m);
				else
					printf("unfiltered%n", &m);
				n += m;
			}
			printf("%*c", 18 - n, ' ');
			if (servi)
				printf("%s\n", servi->s_name);
			else
				printf("unknown\n");
		}
	}
}
