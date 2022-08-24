#include "help.h"
#include "args.h"
#include "ft_nmap.h"

/*
** Quick reminder on ft_getopt "lib"
** Each call to ft_getopt will return either the option 
** or an identifier depends the type, short or long options
** The structure s_optdesc dscribe each options we can get
** {name, Arg or not, address of the flag to set, short identifier, description}
** At each call to ft_getopt, ft_optind and ft_optarg will be updated
** av[ft_optind] will then give the actual option and ft_optarg will be it's parameter
** Warning: dereferencing ft_optarg when option doesn't wait parameter is undefined 
** Option index given to ft_getopt will be update with the id of our option
** This id correspond to it's position inside the descriptor
*/
struct s_optdesc options_descriptor[] = {
	{"help",	NO_ARG, 0, 'h', DESC_HELP},
	{"ip",		ARGREQ, 0, 0, DESC_IP},
	{"file",	ARGREQ, 0, 0, DESC_FILE},
	{"ports",	ARGREQ, 0, 0, DESC_PORTS},
	{"scan",	ARGREQ, 0, 0, DESC_SCAN},
	{"speedup",	ARGREQ, 0, 0, DESC_SPEED},

	{0, 0, 0, 0, 0}
};

void	parse_longoptions(int option_index, char *option, scanconf_t *config) {

	(void)config;
	switch (option_index)
	{
		case 0:
			break ;
		case 1:
			TODO("option ip");
			break ;
		case 2:
			TODO("option file");
			break ;
		case 3:
			printf("FOund ports range\n");
			//config->portrange[0] = atoi(ft_optarg);
			//config->portrange[1] = atoi(strchr(ft_optarg, '-') + 1);
			return ;
		case 4:
			TODO("option scan");
			break ;
		case 5:
			TODO("option speedup");
			break ;
		default:
			printf("Option: %s not found\n", option);
	}

	print_help(options_descriptor);
	getopt_release();
	exit(0);
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
				parse_longoptions(option_index, av[ft_optind], config);
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
	if (config->portrange == NULL) {
		config->portrange = malloc(sizeof(uint32_t) * 1024);
		for (uint32_t i = 0; i < 1024; i++)
			config->portrange[i] = i + 1;
		config->nb_ports = 1024;
	}
	printf("Port range: %d %d\n", config->portrange[0], config->portrange[1]);
	config->targets = g_arglist;
	return 0;
}
