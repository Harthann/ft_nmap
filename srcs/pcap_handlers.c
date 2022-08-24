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

void	free_handlers(struct pcap_t_handlers *handlers)
{
	struct pcap_t_handlers *next;

	while (handlers)
	{
		next = handlers->next;
		pcap_close(handlers->handle);
		handlers = next;
	}
}
