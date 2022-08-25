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

extern pcap_t		*handle;

void		terminate_pcap(int signum)
{
	(void)signum;
	pcap_breakloop(handle);
}

void		setup_pcap_exit(int seconds)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &terminate_pcap;
	sigaction(SIGALRM, &sa, NULL);
	alarm(seconds);
}
