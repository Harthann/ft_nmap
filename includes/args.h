#ifndef ARGS_H
# define ARGS_H

#include "parser.h"
#include "ft_nmap.h"

extern struct s_optdesc options_descriptor[];

#define TODO(string) {printf("Not yet implemented: %s\n", string); return EXIT_FAILURE;}

int			parse_arg(int ac, char **av, scanconf_t *config);

#endif
