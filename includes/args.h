#ifndef ARGS_H
# define ARGS_H

#include "parser.h"
#include "ft_nmap.h"
#include <sys/stat.h>

extern struct s_optdesc options_descriptor[];
extern char	verbose;

#define TODO(string) printf("Not yet implemented: %s\n", string)

int		parse_arg(int ac, char **av, scanconf_t *config);
char	**appendlist(char **list1, char **list2);
char	**addip(char **list, char *ip);
void	freeiplist(char **list);
void	ipfromfile(scanconf_t *config, char *file);
char **split(char *str);

#endif
