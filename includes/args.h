#ifndef ARGS_H
# define ARGS_H

#include "parser.h"

extern struct s_optdesc options_descriptor[];

int			parse_arg(int ac, char **av);

#endif
