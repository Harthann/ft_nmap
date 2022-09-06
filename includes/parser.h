#ifndef PARSER_H
# define PARSER_H

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ARGREQ true
#define NO_ARG false

extern char		*prog_name;

extern int		ft_optind;
extern char		ft_optopt;
extern char		*ft_optarg;
extern char		**g_arglist;


struct s_optdesc {
	char *option;
	bool arg;
	char *flag;
	char shortcut;
	char *desc;
};

char		ft_getopt_long(int ac, char **av, struct s_optdesc *longopt, int *option_index);
void		getopt_release(void);
void		print_args();

#endif
