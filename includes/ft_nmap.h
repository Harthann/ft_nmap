#ifndef FT_NMAP
#define FT_NMAP

/*	Sockets headers */
# include <arpa/inet.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <sys/time.h>
# include <netdb.h>

# include <netinet/in.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>

/* Utils headers */
# include <stdio.h>
# include <stdlib.h>
# include <stdbool.h>
# include <string.h>
# include <errno.h>

# include "logs.h"

# define PROG_NAME "ft_nmap"

#endif
