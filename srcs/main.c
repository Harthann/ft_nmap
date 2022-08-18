#include "parser.h"
#include "help.h"
#include "ft_nmap.h"

char f_flood = 0;


void print_help(struct s_longopt *longopts)
{
	for (int i = 0; longopts && (longopts[i].option || longopts[i].shortcut); i++)
	{
		if (longopts[i].shortcut != 0)
			printf("-%c", longopts[i].shortcut);
		printf("\t");
		if (longopts[i].option != NULL)
			printf("--");
		printf("%-10s", longopts[i].option ? longopts[i].option : "");
		printf(" %s\t", longopts[i].arg ? "[value]":"\t");
		printf("%s\n", longopts[i].desc ? longopts[i].desc : "");
	}
}

int parse_arg(int ac, char **av) {
	char c;

	int option_index = 0;
	static struct s_longopt options[] = {
		{"help", NO_ARG, 0, 'h', DESC_HELP},
		{"ip", ARG_REQ, 0, 'i', DESC_IP},
		{"flood", NO_ARG, &f_flood, 0, 0},
		{NULL, NO_ARG, 0, 'e', DESC_E},
		{0, 0, 0, 0, 0}
	};

	while ((c = ft_getopt_long(ac, av, options, &option_index)) != -1)
	{
		switch (c)
		{
			case 'h':
				print_help(options);
				getopt_release();
				exit(0);
			case 'i':
				printf("This is i opt with arg: %s\n", ft_optarg);
				break ;
			case '!':
				printf("Found long opt %s with arg %s\n", av[ft_optind], ft_optarg);
				break ;
			case '?':
				print_help(options);
				getopt_release();
				exit(0);
		}
	}
	if (g_arglist == NULL) {
		printf("Error: Missing argument\n");
		print_help(options);
		exit (0);
	}
	printf("Arglist:\n");
	for (int i =0; g_arglist[i]; i++)
		printf("%s%c", g_arglist[i], g_arglist[i + 1] ? ' ' : '\n');
	if (f_flood)
		printf("Flooed is activated\n");
	return 0;
}

int main(int ac, char **av)
{
//	if (ac < 2) {
//		print_help();
//		return 0;
//	}

	if (parse_arg(ac - 1, av + 1) != 0)
		return 0;
	return 0;
}
