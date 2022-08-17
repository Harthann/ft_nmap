#include "parser.h"
#include <stdio.h>

/*
** Argument list found along the way 
*/
char				**g_arglist = NULL;

/*
** Index of next option in arg list
*/
int		ft_optind = 0;

/*
** Actual argument
*/
char	ft_optopt = 0;

/*
** This global is a pointer to actual argument value
*/
char	*ft_optarg = 0;

void getopt_release () __attribute__((destructor));

void getopt_release(void) {
	free(g_arglist);
	g_arglist = NULL;
}

/*
** Find next option for one letter options
** Check if we're at the end of optin list
** If no just go to the next option else
** increment to the next program argument
*/
static	void	next_opt(char **av, int *nexti, int *nextj)
{
	(*nextj)++;
	if (av[*nexti][*nextj] == 0)
	{
		(*nexti)++;
		*nextj = 1;
	}
}

/* Initialize the list of long arguments */
//void ft_set_longopt(struct s_longopt *options)
//{
//	static int nb_longopt = 1;
//	void		*tmp = NULL;
//
//	tmp = malloc((nb_longopt + 1) * sizeof(struct s_longopt));
//	memset(tmp, 0, (nb_longopt + 1) * sizeof(struct s_longopt));
//	if (tmp == NULL)
//		exit(-1);
//	if (g_longopt == NULL)
//		g_longopt = tmp;
//	else {
//		memcpy(tmp, g_longopt, nb_longopt * sizeof(struct s_longopt));
//		free(g_longopt);
//		g_longopt = tmp;
//	}
//	g_longopt[nb_longopt - 1].option = option;
//	g_longopt[nb_longopt - 1].arg = arg;
//	nb_longopt += 1;

//}

/*
** Go through all arguments set with ft_set_longopt
** If it found an argument this will setup optind and optarg
** If no corresponding option is found, print an error
** and return '?' telling main program we don't know this opt
*/
static char ft_longopt
(char **av, int *nexti, int *nextj, int *i, struct s_longopt *longopt)
{
	*i = 0;

	for (; longopt[*i].option; (*i)++)
		if (strncmp(av[*nexti] + 2, longopt[*i].option, strlen(av[*nexti])) == 0)
			break ;
	if (longopt[*i].option == NULL) {
		printf("Option not found: %s\n", av[*nexti]);
		return '?';
	}
	if (longopt[*i].arg == true) {
		ft_optarg = av[*nexti + 1];
		*nexti += 2;
	} else {
		ft_optarg = NULL;
		*nexti += 1;
	}
	*nextj = 1;
	if (longopt[*i].shortcut != '\0')
		return longopt[*i].shortcut;
	return '!';
}


static char grow_arglist(char **av, int *nexti, int *nextj)
{
	static int	arglist_len = 1;
	char		**tmp = NULL;

	tmp = malloc((arglist_len + 1) * sizeof(char*));
	memset(tmp, 0, (arglist_len + 1) * sizeof(char*));

	if (g_arglist) {
		memcpy(tmp, g_arglist, arglist_len * sizeof(char*));
		free(g_arglist);
		g_arglist = tmp;
	}
	else {
		g_arglist = tmp;
	}
	arglist_len += 1;
	g_arglist[arglist_len - 2] = av[*nexti];
	*nexti += 1;
	*nextj = 1;
	return '\0';
}

void print_args()
{
	int i = 0;

	while (g_arglist[i]) {
		printf("%s\n", g_arglist[i++]);
	}
}

/*
**	This will go through all program argument memorizing
**	where we are on the list. If we found long argument
**	we simply pass it ft_longopt argument
**	if not we setup either and argument in g_arglist
**	with grow_arglist or return the actual option found
*/
char	ft_getopt
(int ac, char **av, const char *flags, struct s_longopt *longopt, int *option_index)
{
	/* Correspond to the position inside argument list */
	static int nexti = 0;

	/* Correspond to the position inside the argument itself */
	static int nextj = 1;

	ft_optind = nexti;
	if (nexti >= ac)
		return -1;
	if (av[nexti][0] != '-')
		return grow_arglist(av, &nexti, &nextj);
	if (av[nexti][0] == '-' && av[nexti][1] == '-')
		return ft_longopt(av, &nexti, &nextj, option_index, longopt);
	ft_optopt = av[nexti][nextj];

	/* No longopt found, checking for normal options */
	for (int i = 0; flags && flags[i]; i++)
	{
		if (flags[i] == ft_optopt)
		{
			if (flags[i + 1] != ':')
			{
				next_opt(av, &nexti, &nextj);
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

