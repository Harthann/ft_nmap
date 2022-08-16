#include "parser.h"
#include "ft_nmap.h"

void print_help()
{
	printf("This is help\n");
}

void init_options(void) {
	ft_set_longopt("--help", false);
	ft_set_longopt("--string", false);
}

int parse_arg(int ac, char **av) {
	char c;

	init_options();
	while ((c = ft_getopt(ac, av, "h")) != -1)
	{
		switch (c)
		{
			case 'h':
				print_help();
				getopt_release();
				exit(0);
			case 'i':
				printf("This is i arg\n");
				break ;
			case '!':
				printf("Found long arg\n");
				break ;
			case '?':
				print_help();
				getopt_release();
				exit(0);
		}
	}
	printf("Optind: %d\n", ft_optind);
	printf("Arg: %s\n", av[ft_optind]);
	getopt_release();
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
