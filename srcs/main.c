#include "ft_nmap.h"
#include "args.h"

char f_flood = 0;
char *prog_name = NULL;

int			main(int ac, char **av)
{
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
	free(prog_name);
	return EXIT_SUCCESS;
}
