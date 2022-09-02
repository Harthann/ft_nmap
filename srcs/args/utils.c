#include "args.h"

int		is_numeric(char *str) {

	if (*str == '-')
		str += 1;

	while (*str) {
		if (*str < '0' || *str > '9')
			return 0;
		str += 1;
	}

	return 1;
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

/*
** Add a scan to verbosity flag
** Syn: S
** Null: N
** Fin: F
** Xmas: X
** Udp: U
*/
int	addscan(char *str)
{
	int length = 0;

	while (str[length])
		length += 1;

	printf("Found arg: {%s} %d\n", str, length);
	if ((length == 1 && str[0] == 'S') || !strcmp(str, "SYN")) {
		verbose |= SCAN_SYN;
		return 1;
	}
	else if ((length == 1 && str[0] == 'A') || !strcmp(str, "ACK")) {
		verbose |= SCAN_ACK;
		return 1;
	}
	else if ((length == 1 && str[0] == 'N') || !strcmp(str, "NULL")) {
		verbose |= SCAN_NULL;
		return 1;
	}
	else if ((length == 1 && str[0] == 'F') || !strcmp(str, "FIN")) {
		verbose |= SCAN_FIN;
		return 1;
	}
	else if ((length == 1 && str[0] == 'X') || !strcmp(str, "XMAS")) {
		verbose |= SCAN_XMAS;
		return 1;
	}
	else if ((length == 1 && str[0] == 'U') || !strcmp(str, "UDP")) {
		verbose |= SCAN_UDP;
		return 1;
	}

	return 0;
}
