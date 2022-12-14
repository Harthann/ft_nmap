#ifndef ARGS_H
# define ARGS_H

#include "parser.h"
#include "ft_nmap.h"
#include <sys/stat.h>

extern struct s_optdesc options_descriptor[];
extern char	verbose;


#define VERBOSITY	0x01
#define SCAN_SYN	0x02
#define SCAN_NULL	0x04
#define SCAN_ACK	0x08
#define SCAN_FIN	0x10
#define SCAN_XMAS	0x20
#define SCAN_UDP	0x40
#define SETUP_PORT	0x80

#define TODO(string) printf("Not yet implemented: %s\n", string)

int		parse_arg(int ac, char **av, scanconf_t *config);
char	**appendlist(char **list1, char **list2);
char	**addip(char **list, char *ip);
void	freeiplist(char **list);
int		ipfromfile(scanconf_t *config, char *file);
char	**split(char *str);
int		is_numeric(char *str);
int		addscan(char *str);
int		create_range(char *list, scanconf_t *config);
void		sort_array(uint32_t *array, uint32_t length);

#endif
