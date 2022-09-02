#include "args.h"

static inline int	find_nextsep(char *list, int nextsep)
{
	while (list[nextsep] && (list[nextsep] != '-' && list[nextsep] != ','))
			nextsep += 1;
	return nextsep;
}

static int	addrange(int start, int end, scanconf_t *config)
{
	uint32_t	*tmp = NULL;
	uint32_t	inc = 0;

	printf("Range found from %d to %d\n", start, end);
	inc = end - start;
	if (start < 0 || end < 0 ||	start > MAX_PORT || end > MAX_PORT ) {
		fprintf(stderr, "Error! Invalid port range\n");
		return EXIT_FAILURE;
	}
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
	for (uint32_t i = config->nb_ports - inc; i < config->nb_ports; i++) {
		config->portrange[i] = start;
		start += 1;
	}

	return EXIT_SUCCESS;
}

int	create_range(char *list, scanconf_t *config)
{
	int			index = 0;
	int			nextsep = 0;
	uint32_t	*tmp = NULL;

	(void)tmp;
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
			config->portrange[config->nb_ports - 1] = atoi(list + index);
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
