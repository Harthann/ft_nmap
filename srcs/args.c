#include "help.h"
#include "args.h"
#include "ft_nmap.h"

struct s_optdesc options_descriptor[] = {
	{"help",	NO_ARG, 0, 'h', DESC_HELP},
	{"ip",		ARGREQ, 0, 0, DESC_IP},
	{"file",	ARGREQ, 0, 0, DESC_FILE},
	{"ports",	ARGREQ, 0, 0, DESC_PORTS},
	{"scan",	ARGREQ, 0, 0, DESC_SCAN},
	{"speedup",	ARGREQ, 0, 0, DESC_SPEED},
/* Describing options with global flag variable separately */
//		{"flood",	NO_ARG, &f_flood, 0, 0},
	{0, 0, 0, 0, 0}
};


int			parse_arg(int ac, char **av) {
	char c;

	int option_index = 0;


	while ((c = ft_getopt_long(ac, av, options_descriptor, &option_index)) != -1)
	{
		switch (c)
		{
			case 'h':
				print_help(options_descriptor);
				getopt_release();
				exit(0);
			case 'i':
				printf("This is i opt with arg: %s\n", ft_optarg);
				break ;
			case '!':
				printf("Found long opt %s with arg %s\n", av[ft_optind], ft_optarg);
				break ;
			case '?':
				print_help(options_descriptor);
				getopt_release();
				exit(0);
		}
	}
	if (g_arglist == NULL) {
		printf("Error: Missing argument\n");
		print_help(options_descriptor);
		return EXIT_FAILURE;
	}
	for (int i =0; g_arglist[i]; i++)
		printf("%s%c", g_arglist[i], g_arglist[i + 1] ? ' ' : '\n');
	return 0;
}
