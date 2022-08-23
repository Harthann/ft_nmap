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

int			parse_longoptions(int option_index, char *option, scanconf_t *config) {

	(void)config;
	switch (option_index)
	{
		case 0:
			return EXIT_FAILURE;
		case 1:
			TODO("option ip");
		case 2:
			TODO("option file");
		case 3:
			TODO("option ports");
		case 4:
			TODO("option scan");
		case 5:
			TODO("option speedup");
	}

	printf("Option: %s not found\n", option);
	return EXIT_FAILURE;
}


int			parse_arg(int ac, char **av, scanconf_t *config) {
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
			case '!':
				if (parse_longoptions(option_index, av[ft_optind], config) == EXIT_FAILURE) {
					print_help(options_descriptor);
					getopt_release();
					exit(0);
				}
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
	return 0;
}
