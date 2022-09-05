#include "args.h"

static inline int	find_nextsep(char *list, int nextsep)
{
	while (list[nextsep] && (list[nextsep] != '-' && list[nextsep] != ','))
			nextsep += 1;
	return nextsep;
}

int		isdup(uint32_t port, uint32_t *range, uint32_t length)
{
	for(uint32_t i = 0; range && i < length; i++) {
		if (range[i] == port)
			return 1;
	}
	return 0;
}

static int	count(int start, int end, uint32_t *range, uint32_t length)
{
	int count = 0;

	while (start != end) {
		if (!isdup(start, range, length))
			count += 1;
		start += 1;
	}
	return count;
}

static int	addrange(int start, int end, scanconf_t *config)
{
	uint32_t	*tmp = NULL;
	uint32_t	inc = 0;

	if (start < 0 || end < 0 || start > MAX_PORT || end > MAX_PORT ) {
		fprintf(stderr, "Error! Invalid port range\n");
		return EXIT_FAILURE;
	}

	inc = count(start, end, config->portrange, config->nb_ports);
	if (inc > 1024) {
		fprintf(stderr, "Error! Portrange too big\n");
		return EXIT_FAILURE;
	}

	config->nb_ports += inc;
	tmp = calloc(sizeof(uint32_t), config->nb_ports);
	if (!tmp) {
		fprintf(stderr, "Error! Allocation failed for portrange\n");
		return EXIT_FAILURE;
	}

	if (config->portrange) {
		memcpy(tmp, config->portrange, sizeof(uint32_t) * (config->nb_ports - 1 - inc));
		free(config->portrange);
	}
	config->portrange = tmp;
	printf("Starting loop at: {%d}\n", config->portrange[config->nb_ports - inc - 1]);
	for (uint32_t i = config->nb_ports - inc; i < config->nb_ports; i++) {
		printf("{%d} {%d}\n", config->portrange[i], start);
		if (!isdup(start, config->portrange, config->nb_ports - inc))
			config->portrange[i] = start;
		start += 1;
	}

	return EXIT_SUCCESS;
}

int	create_range(char *list, scanconf_t *config)
{
	int			index = 0;
	int			nextsep = 0;
	uint32_t		*tmp = NULL;
	uint32_t		newport;

	while (list[index]) {
		nextsep = find_nextsep(list, index);
		if (list[nextsep] && list[nextsep] == '-') {
		 	if (addrange(atoi(list + index), atoi(list + nextsep + 1), config) == EXIT_FAILURE) {
				goto reterror;
			}
			index = nextsep;
			nextsep = find_nextsep(list, index + 1);
		}
		else {
			newport = atoi(list + index);
			if (!isdup(newport, config->portrange, config->nb_ports)) {
				config->nb_ports += 1;
				tmp = calloc(sizeof(uint32_t), config->nb_ports);
				if (!tmp) {
					fprintf(stderr, "Error! Allocation failed for portrange\n");
					goto reterror;
				}
				if (config->portrange) {
					memcpy(tmp, config->portrange, sizeof(uint32_t) * (config->nb_ports - 1));
					free(config->portrange);
				}
				config->portrange = tmp;
				if (newport > MAX_PORT) {
					fprintf(stderr, "Error! Invalid port {%d}\n", newport);
					goto reterror;
				}
				config->portrange[config->nb_ports - 1] = newport;
			}
		}
		if (!list[nextsep])
			break;
		index = nextsep + 1;
	}
	return EXIT_SUCCESS;

reterror:
	free(config->portrange);
	config->portrange = NULL;
	return EXIT_FAILURE;
}
