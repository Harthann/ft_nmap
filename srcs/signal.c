#include "ft_nmap.h"

void		signal_handler(int signum)
{
	printf("\b\b  \b\b\n");
	exit(128 + signum);
}

void		handling_signals()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &signal_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
}
