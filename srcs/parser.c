#include "parser.h"
#include <stdio.h>

struct s_longopt *g_longopt = NULL;

/* Index of next option in arg list */
int		ft_optind = 0;

/* Actual argument */
char	ft_optopt = 0;

/* This global is a pointer to actual argument value */
char	*ft_optarg = 0;

static	void	next_opt(int ac, char **av, int *nexti, int *nextj)
{
	(void)ac;
	(*nextj)++;
	if (av[*nexti][*nextj] == 0)
	{
		(*nexti)++;
		*nextj = 1;
	}
}

void ft_set_longopt(char *option, bool arg)
{
	static int nb_longopt = 1;
	void		*tmp = NULL;

	tmp = malloc((nb_longopt + 1) * sizeof(struct s_longopt));
	memset(tmp, 0, (nb_longopt + 1) * sizeof(struct s_longopt));
	if (tmp == NULL)
		exit(-1);
	if (g_longopt == NULL)
		g_longopt = tmp;
	else {
		memcpy(tmp, g_longopt, nb_longopt * sizeof(struct s_longopt));
		free(g_longopt);
		g_longopt = tmp;
	}
	g_longopt[nb_longopt - 1].option = option;
	g_longopt[nb_longopt - 1].arg = arg;
	nb_longopt += 1;

}

static char ft_longopt(int ac, char **av, int *nexti, int *nextj)
{
	(void)ac;(void)av;(void)nexti;(void)nextj;
	// Look for long arg
	// if exist with arg update optarg
	// if exist without arg
	for (int i = 0; g_longopt[i].option; i++)
		printf("%s\n", g_longopt[i].option);
	*nexti += 1;
	*nextj = 1;
	return '!';
}

void getopt_release(void) {
	free(g_longopt);
}

/*
 **	Litle reimplementation of getopt lib
 **	
 */
char	ft_getopt(int ac, char **av, const char *flags)
{
	static int nexti = 0;
	static int nextj = 1;

	ft_optind = nexti;
	if (nexti >= ac || av[nexti][0] != '-')
		return -1;
	if (av[nexti][0] == '-' && av[nexti][1] == '-')
		return ft_longopt(ac, av, &nexti, &nextj);
	ft_optopt = av[nexti][nextj];
	for (int i = 0; flags && flags[i]; i++)
	{
		if (flags[i] == ft_optopt)
		{
			if (flags[i + 1] != ':')
			{
				next_opt(ac, av, &nexti, &nextj);
				return ft_optopt;
			}
			if (av[nexti][nextj + 1])
			{
				ft_optarg = av[nexti] + nextj + 1;
				nexti++;
				nextj = 1;
				return ft_optopt;
			}
			ft_optarg = av[nexti + 1];
			nexti += 2;
			nextj = 1;
			return ft_optopt;
		}
	}
	return '?';
}
