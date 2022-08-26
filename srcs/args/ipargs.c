#include "args.h"

char	**addip(char **list, char *ip) {
	static int length = 1;
	char		**tmp;

	tmp = calloc(sizeof(char*), length + 1);
	if (!tmp) {
		freeiplist(list);
		return NULL;
	}
	if (list) {
		memcpy(tmp, list, length * sizeof(char*));
		free(list);
	}
	tmp[length - 1] = strdup(ip);
	length += 1;

	return tmp;
}

/*
** Create a new list by appending list2 at list1
** Find each list length using i and j respectively
** for the length of list1 and list2
*/
char	**appendlist(char **list1, char **list2) {
	char	**dst	= NULL;
	int		i		= 0;
	int		j		= 0;

	while (list1 && list1[i])
		i += 1;
	while (list2 && list2[j])
		j += 1;
	
	dst = calloc((i + j + 1), sizeof(char*));
	if (dst && list1)
		memcpy(dst, list1, sizeof(char*) * i);
	if (dst && list2)
		memcpy(dst + i, list2, sizeof(char*) * j);

	free(list1);
	free(list2);
	return dst;
}

void	ipfromfile(scanconf_t *config, char *file)
{
	FILE		*fd;
	struct stat stat_file;
	char		*buffer;
	char		**lines;

/*
** Get stat of file to check whether it's valid or not
** Then get it's size to map it in memory using mmap
*/
	if (stat(file, &stat_file) != 0) {
		fprintf(stderr, "%s: Stat file: %s\n", prog_name, strerror(errno));
		return ;
	}
	if (S_ISDIR(stat_file.st_mode)) {
		fprintf(stdout, "%s is a directory\n", file);
		return ;
	}
	fd = fopen(file, "r");

/*
** Map the file in memory using mmap then splitting it in lines
*/
	buffer = calloc(stat_file.st_size + 1, sizeof(char));
	if (!buffer) {
		fprintf(stderr, "%s: Stat file: %s\n", prog_name, strerror(errno));
		return ;
	}
	fread(buffer, stat_file.st_size, 1, fd);

	lines = split(buffer);
	if (!lines)
		return ;

	for (int i = 0; lines[i]; i++)
		printf("%s\n", lines[i]);
	config->targets = appendlist(config->targets, lines);
	free(buffer);
}

char **split(char *str) {
	int		words = 0;
	int		count = 0;
	char	*tmp = str;
	char	**dst = NULL;

	while (*tmp) {
		if (*tmp == '\n')
			words += 1;
		tmp += 1;
	}

	dst = calloc(words + 1, sizeof(char*));
	if (!dst)
		return NULL;

	tmp = str;
	for (int i = 0; i < words; i++) {
		count = 0;
		while (tmp[count] != '\n' && tmp[count])
			count += 1;

		dst[i] = calloc(count + 1, sizeof(char));
		if (dst[i]) {
			memcpy(dst[i], tmp, count);
			tmp += count + 1;
		} else {
			freeiplist(dst);
			return NULL;
		}
	}

	return dst;
}

void	freeiplist(char **list) {
	char **tmp = list;

	while (list && *list) {
		free(*list);
		list += 1;
	}
	free(tmp);
}
