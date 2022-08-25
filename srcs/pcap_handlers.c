#include "ft_nmap.h"

/*
** Add a new entry to the list of pcap handler
** Will return a non modified list if allocation fail
** Return the new head of the list
*/
struct pcap_t_handlers *new_handlerentry(struct pcap_t_handlers *head, pcap_t *handle)
{
	struct pcap_t_handlers *nentry;

	nentry = malloc(sizeof(struct pcap_t_handlers));
	if (nentry == NULL)
		return head;

	nentry->handle = handle;
	nentry->next = head;

	return nentry;
}

/*
** Release all handlers and free the list
*/
void	free_handlers(struct pcap_t_handlers *handlers)
{
	struct pcap_t_handlers *next;

	while (handlers)
	{
		next = handlers->next;
		pcap_close(handlers->handle);
		free(handlers);
		handlers = next;
	}
}

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
