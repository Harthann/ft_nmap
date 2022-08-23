#include "ft_nmap.h"

/*
** Add a new entry to the list of scans sended
** Will return a non modified list if allocaiton fail
** Return the new head of the list
*/
struct scan_s *new_scanentry(struct scan_s *head, void *buffer)
{
	struct scan_s *nentry;

	nentry = malloc(sizeof(struct scan_s));
	if (nentry == NULL)
		return head;

	nentry->packet = buffer;
	nentry->next = head;

	return nentry;
}

void print_scanlist(struct scan_s *scanlist)
{
	int					id;
	struct iphdr		*iphdr;
	struct tcphdr		*tcphdr;
	struct icmphdr		*icmphdr;
	struct udp			*udphdr;

	id = 0;
	while (scanlist) {
		iphdr =  scanlist->packet;
		switch (iphdr->protocol)
		{
			case IPPROTO_TCP:
				tcphdr =  scanlist->packet + sizeof(struct iphdr);
				printf("Scan %d TCP: {\nType: %#x\nSaddr: %#x\nDaddr: %#x\nDport: %u\nSport: %u\n}\n", id, tcphdr->syn, iphdr->daddr, iphdr->saddr, tcphdr->dest, ntohs(tcphdr->source));
				break ;
			case IPPROTO_UDP:
				udphdr = scanlist->packet + sizeof(struct iphdr);
				(void)udphdr;
				printf("Scan: %d UDP\n", id);
				break ;
			case IPPROTO_ICMP:
				icmphdr = scanlist->packet + sizeof(struct iphdr);
				(void)icmphdr;
				printf("Scan: %d ICMP\n", id);
				break ;
			default:
				printf("Scan: %d UNKNOWN\n", id);
		}
		scanlist = scanlist->next;
		id += 1;
	}
}

void	free_scanlist(struct scan_s *scanlist)
{
	struct scan_s *next;

	while (scanlist)
	{
		next = scanlist->next;
		free(scanlist);
		scanlist = next;
	}
}

/*
** Use response buffer to look inside list of performed scan
** If we find it it means it correspond to one of our scan
** and is ready to be checked
*/
bool	find_scan(void* buffer, struct scan_s *scanlist)
{
	(void)buffer;
	(void)scanlist;
	return true;
}
