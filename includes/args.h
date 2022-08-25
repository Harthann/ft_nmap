#ifndef ARGS_H
# define ARGS_H

#include "parser.h"
#include "ft_nmap.h"

extern struct s_optdesc options_descriptor[];
extern char	verbose;

#define TODO(string) printf("Not yet implemented: %s\n", string)

int			parse_arg(int ac, char **av, scanconf_t *config);

#endif
