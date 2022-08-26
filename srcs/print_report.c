#include "ft_nmap.h"
#include "args.h"

int		should_print(uint8_t flags, int max_flag)
{
	if (verbose & VERBOSITY)
		return 1;
	if (flags != max_flag)
		return 1;
	return 0;
}

void	print_report(t_port_status *ports, uint32_t nb_ports, char *target, char *target_ip)
{
	struct servent* servi;
	int				flags[16] = {0};
	int				max_flag;
	int				max_value;

	for (uint32_t i = 0; i < nb_ports; i++)
		flags[ports[i].flags]++;
	max_flag = 0;
	max_value = -1;
	for (int i = 0; i < 16; i++)
	{
		if (flags[i] > max_value)
		{
			max_flag = i;
			max_value = flags[i];
		}
	}

	printf("%s scan report for %s (%s)\n", prog_name, target, target_ip);
	printf("Not shown: %d ", max_value);
	if (max_flag & SET_ACCESS) {
		printf("%s", max_flag & OPEN ? "opened" : "closed");
	}

	if (max_flag & SET_FILTER) {
		if (max_flag & SET_ACCESS)
			printf("|");
		printf("%s", max_flag & FILTERED ? "filtered" : "unfiltered");
	}
	printf(" ports.\n");
	printf("PORT      STATUS            SERVICE\n");
	for (uint32_t i = 0; i < nb_ports; i++)
	{
		if (should_print(ports[i].flags, max_flag)) {//(ports[i].flags & SET_ACCESS || ports[i].flags & SET_FILTER) {
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
