#include "parser.h"

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

//void getopt_release () __attribute__((destructor));

void getopt_release(void) {
	int i = 0;

	while (g_arglist && g_arglist[i])
		free(g_arglist[i++]);
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

/*
** Go through all arguments set with ft_set_longopt
** If it found an argument this will setup optind and optarg
** If no corresponding option is found, print an error
** and return '?' telling main program we don't know this opt
*/
static char ft_longopt
(char **av, int *nexti, int *nextj, int *i, struct s_optdesc *longopt)
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
	if (longopt[*i].flag != NULL)
		*longopt[*i].flag |= 1;
	if (longopt[*i].shortcut != '\0' || longopt[*i].flag != NULL)
		return longopt[*i].shortcut;
	return '!';
}


static char grow_arglist(char **av, int *nexti, int *nextj)
{
	static int	arglist_len = 1;
	char		**tmp = NULL;

	tmp = malloc((arglist_len + 1) * sizeof(char*));
	if (!tmp) {
		fprintf(stderr, "%s: malloc(): %s\n", prog_name, strerror(errno));
		return '\0';
	}
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
	g_arglist[arglist_len - 2] = strdup(av[*nexti]);
	*nexti += 1;
	*nextj = 1;
	return '\0';
}


/*
**	This will go through all program argument memorizing
**	where we are on the list. If we found long argument
**	we simply pass it ft_longopt argument
**	if not we setup either and argument in g_arglist
**	with grow_arglist or return the actual option found
*/
char	ft_getopt_long
(int ac, char **av, struct s_optdesc *longopt, int *option_index)
{
/* Correspond to the position inside argument list */
	static int nexti = 0;

/* Correspond to the position inside the argument itself */
	static int nextj = 1;

/* Options index inside flags or longopts */
	int index = -1;
	ft_optind = nexti;
	if (nexti >= ac)
		return -1;
	if (av[nexti][0] != '-')
		return grow_arglist(av, &nexti, &nextj);
	if (av[nexti][0] == '-' && av[nexti][1] == '-')
		return ft_longopt(av, &nexti, &nextj, option_index, longopt);
	ft_optopt = av[nexti][nextj];

/*
** Lookup for shorthand option in the list
** If option doesn't require parameter simply return it
** and set flag if possible
** If it does require an argument continue to the next block
*/
	for (int i = 0; longopt && (longopt[i].option || longopt[i].shortcut); i++)
		if (longopt[i].shortcut == ft_optopt) {
			index = i;
		}

/*
** If index still equal to -1 this means we didn't found the option
*/
	if (index == -1) {
		printf("Option not found: -%c\n", av[nexti][nextj]);
		return '?';
	}

/*
** If the option doesn't require an argument this will return it
** Setting up a flag if needed before
*/
	if (longopt[index].arg == false)
	{
		if (longopt[index].flag != NULL)
			*longopt[index].flag |= 1;
		next_opt(av, &nexti, &nextj);
		return ft_optopt;
	}

/*
** Short hand option found, extracting argument
** from either next arg or right after option
** Ex: -i1234 -i 12344
*/
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

