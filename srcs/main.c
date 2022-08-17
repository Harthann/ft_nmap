#include "parser.h"
#include "ft_nmap.h"

void print_help()
{
	printf("This is help\n");
}

int parse_arg(int ac, char **av) {
	char c;

	int option_index = 0;
	static struct s_longopt longopts[] = {
		{"help", NO_ARG, 'h'},
		{"string", ARG_REQ, 0},
		{"ip", ARG_REQ, 0},
		{0, 0, 0}
	};

	while ((c = ft_getopt(ac, av, "hi:", longopts, &option_index)) != -1)
	{
		switch (c)
		{
			case 'h':
				print_help();
				getopt_release();
				exit(0);
			case 'i':
				printf("This is i opt with arg: %s\n", ft_optarg);
				break ;
			case '!':
				printf("Found long opt %s with arg %s\n", av[ft_optind], ft_optarg);
				break ;
			case '?':
				print_help();
				getopt_release();
				exit(0);
		}
	}
	printf("Arglist:\n");
	for (int i =0; g_arglist[i]; i++)
		printf("%s%c", g_arglist[i], g_arglist[i + 1] ? ' ' : '\n');
	return 0;
}

int main(int ac, char **av)
{
	if (ac < 2) {
		print_help();
		return 0;
	}

	if (parse_arg(ac - 1, av + 1) != 0)
		return 0;
	return 0;
}
