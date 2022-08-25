#include "ft_nmap.h"

/*
** Setup a filter for a pcap handler
*/
int			pcap_setup_filter(pcap_t *handle, struct bpf_program *fp, bpf_u_int32 net, char *filter)
{
	if (pcap_compile(handle, fp, filter, 0, net) == PCAP_ERROR)
	{
		fprintf(stderr, "%s: pcap_compile: %s: %s\n", prog_name, filter, pcap_geterr(handle));
		return EXIT_FAILURE;
	}
	if (pcap_setfilter(handle, fp) == PCAP_ERROR)
	{
		fprintf(stderr, "%s: pcap_setfilter: %s: %s\n", prog_name, filter, pcap_geterr(handle));
		pcap_freecode(fp);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
