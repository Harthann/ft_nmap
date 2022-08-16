#ifndef PARSER_H
# define PARSER_H

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

char		ft_getopt(int ac, char **v, const char *flags);
void		ft_set_longopt(char *option, bool arg);
void		getopt_release(void);

extern	int		ft_optind;
extern	char	ft_optopt;
extern	char	*ft_optarg;

struct s_longopt {
	char *option;
	bool arg;
};

#endif
