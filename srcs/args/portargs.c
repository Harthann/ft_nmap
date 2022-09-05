#include "args.h"

static inline int	find_nextsep(char *list)
{
	int i = 0;

	while (list && list[i] && list[i] != ',')
		i += 1;
	return i;
}

static inline bool	isrange(char *list, int length)
{
	for (int i = 0; i < length; i++) {
		if (list[i] == '-')
			return true;
	}
	return false;
}

/*
** Look inside range if a port is already added
*/
static inline bool isdup(uint32_t port, uint32_t *range, uint32_t length)
{
	for (uint32_t i = 0; range && i < length; i++)
		if (range[i] == port)
			return true;
	return false;
}

/*
** Add multiple port to range form args
** Format is start-end
** If any number is missing it will ne interpreted as 0
*/
static int	addrange(char *list, uint32_t **portrange, uint32_t *length)
{
	int		start;
	int		end;
	int		inc = 0;
	uint32_t	*range = NULL;
	

	start = atoi(list);
	while (*list != '-')
		list += 1;
	end = atoi(list + 1);

	if (end < start) {
		fprintf(stderr,"Error! Invalid backward range {%d} {%d}\n", start, end);
		return EXIT_FAILURE;
	}

	for (int i = start; i < end; i++)
		if (!isdup(i, *portrange, *length))
			inc += 1;

	range = calloc(sizeof(uint32_t), inc + *length);
	if (!range) {
		fprintf(stderr, "Error! Allocation failed\n");
		return EXIT_FAILURE;
	}
	if (*portrange)
		memcpy(range, *portrange, *length * sizeof(uint32_t));
	for (int i = 0; i < inc; start += 1) {
		if (!isdup(start, range, *length)) {
			range[*length + i] = start;
			i += 1;
		}
	}

	free(*portrange);
	*portrange = range;
	*length += inc;

	return EXIT_SUCCESS;
}


/*
** Increase portrange length by one and append the new port at the end
*/
static int addport(char *list, uint32_t **portrange, uint32_t *length)
{
	int		port;
	uint32_t	*range;

	port = atoi(list);

	if (port > MAX_PORT) {
		fprintf(stderr, "Error! Ports can't be higher than %d\n", MAX_PORT);
		return EXIT_FAILURE;
	}
	if (isdup(port, *portrange, *length))
		return EXIT_SUCCESS;

	range = calloc(sizeof(uint32_t), *length + 1);
	if (!range) {
		fprintf(stderr, "Error! Allocation failed\n");
		return EXIT_FAILURE;
	}
	if (*portrange)
		memcpy(range, *portrange, *length * sizeof(uint32_t));
	range[*length] = port;

	free(*portrange);
	*portrange = range;
	*length += 1;

	return EXIT_SUCCESS;
}

int	create_range(char *list, scanconf_t *config)
{
	uint32_t	*portrange = NULL;
	uint32_t	length = 0;

	int		nextsep = 0;

	(void)config;
	while (list && *list) {
		if (*list == ',')
			list += 1;

		nextsep = find_nextsep(list);
		if (isrange(list, nextsep)) {
			if (addrange(list, &portrange, &length) == EXIT_FAILURE)
				goto reterror;
		} else {
			if (addport(list, &portrange, &length) == EXIT_FAILURE) 
				goto reterror;
		}
		printf("{%s} {%d}\n", list, nextsep);

		list += nextsep;
	}

	config->portrange = portrange;
	config->nb_ports = length;
	return EXIT_SUCCESS;

reterror:
	free(portrange);
	return EXIT_FAILURE;
}

