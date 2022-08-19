#include "help.h"
#include "parser.h"
#include "ft_nmap.h"
#include "args.h"

extern char *prog_name;

void		print_help(struct s_optdesc *longopts)
{
	printf("Usage:\n");
	printf("  %s [--option [arg]] --file FILE\n", prog_name);
	printf("  %s [--option [arg]] --ip IP/RANGE\n\n", prog_name);
	printf("Options:\n");
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
