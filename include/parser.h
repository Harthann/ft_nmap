#ifndef PARSER_H
# define PARSER_H

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#define ARG_REQ true
#define NO_ARG false

extern	int		ft_optind;
extern	char	ft_optopt;
extern	char	*ft_optarg;
extern	char	**g_arglist;

struct s_longopt {
	char *option;
	bool arg;
	char *flag;
	char shortcut;
	char *desc;
};


char		ft_getopt_long(int ac, char **av, struct s_longopt *longopt, int *option_index);
void		getopt_release(void);
void print_args();



#endif
