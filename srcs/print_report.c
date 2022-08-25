#include "ft_nmap.h"
#include "args.h"

int		should_print(uint8_t flags, int filtered, int open)
{
	if (verbose)
		return 1;
	if ((flags & SET_ACCESS) && (flags & OPEN) && open < filtered)
		return 1;
	if ((flags & SET_FILTER) && (flags & FILTERED) && filtered < open)
		return 1;
	return 0;
}

void	print_report(t_port_status *ports, uint32_t nb_ports, char *target, char *target_ip)
{
	struct servent* servi;
	int				filtered = 0;
	int				open = 0;

	for (uint32_t i = 0; i < nb_ports; i++) {
		if (ports[i].flags & SET_FILTER && ports[i].flags & FILTERED)
			filtered += 1;
		else if (ports[i].flags & SET_ACCESS && ports[i].flags & OPEN)
			open += 1;
	}

	printf("%s scan report for %s (%s)\n", prog_name, target, target_ip);
	printf("%d filtered, %d open on %d ports.\n", filtered, open, nb_ports);
	printf("PORT      STATUS            SERVICE\n");


	for (uint32_t i = 0; i < nb_ports; i++)
	{
		if (should_print(ports[i].flags, filtered, open)) {//(ports[i].flags & SET_ACCESS || ports[i].flags & SET_FILTER) {
			int		n;
			int		m = 0;

			printf("%d/tcp%n", ports[i].port, &n);
			printf("%*c", 10 - n, ' ');
			servi = getservbyport(htons(ports[i].port), "tcp");

			if (ports[i].flags & SET_ACCESS) {
				printf("%s%n", ports[i].flags & OPEN ? "open" : "close", &n);
			}

			if (ports[i].flags & SET_FILTER) {
				if (ports[i].flags & SET_ACCESS) {
					printf("|");
					n++;
				}
				printf("%s%n", ports[i].flags & FILTERED ? "filtered" : "unfiltered", &m);
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
