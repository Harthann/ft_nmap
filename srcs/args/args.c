#include "help.h"
#include "args.h"
#include "ft_nmap.h"

char verbose = 0;

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
	{"scan",	ARGREQ, 0, 's', DESC_SCAN},
	{"speedup",	ARGREQ, 0, 0, DESC_SPEED},
	{"verbose", NO_ARG, &verbose, 'v', DESC_VERB},

	{0, 0, 0, 0, 0}
};

void	parse_longoptions(int option_index, char *option, scanconf_t *config) {

	switch (option_index)
	{
		case 0:
			break ;

		case 1:
			config->targets = addip(config->targets, ft_optarg);
			return ;

		case 2:
			ipfromfile(config, ft_optarg);
			return ;

		case 3:
			printf("Found ports range\n");
			return ;

		case 4:
			// This option is handle using it's shorthand option
			return ;

		case 5:
			if (!is_numeric(ft_optarg) || ft_optarg[0] == '-') {
				printf("Threads number should be a positive integer between 0 and 255\n");
				break;
			}
			config->nb_threads = atoi(ft_optarg);
			if (config->nb_threads > 255) {
				printf("Threads number should be a positive integer between 0 and 255\n");
				break;
			}
			return ;

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
				freeiplist(config->targets);
				free(prog_name);
				exit(0);
			case 's':
				if (!addscan(ft_optarg)) {
					printf("Scan {%s} not known\n", ft_optarg);
					print_help(options_descriptor);
					return EXIT_FAILURE;
				}
				break ;
			case '!':
				parse_longoptions(option_index, av[ft_optind], config);
				printf("Found long opt\n");
				break ;
			case '?':
				print_help(options_descriptor);
				return EXIT_FAILURE;
		}
	}
	if (g_arglist == NULL && config->targets == NULL) {
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
	if (config->nb_threads > config->nb_ports)
		config->nb_threads = config->nb_ports;

	printf("Threads nummber: %d\n", config->nb_threads);
	if (verbose == 0 || verbose == 1)
		verbose |= SCAN_SYN | SCAN_NULL | SCAN_FIN | SCAN_XMAS | SCAN_ACK | SCAN_UDP;
	printf("Asked scan: %d\n", verbose);
	config->targets = appendlist(config->targets, g_arglist);
	return 0;
}