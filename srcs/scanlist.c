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

	nentry->iphdr = (struct iphdr*)buffer;
	nentry->tcphdr = (struct tcphdr*)(buffer + sizeof(struct iphdr));
	nentry->next = head;

	return nentry;
}

void print_scanlist(struct scan_s *scanlist)
{
	int id = 0;
	struct iphdr *ip;
	struct tcphdr *tcp;

	while (scanlist) {
		ip =  scanlist->iphdr;
		tcp =  scanlist->tcphdr;
		printf("Scan %d: {\nType: %#x\nSaddr: %#x\nDaddr: %#x\nDport: %u\nSport: %u\n}\n", id
	, tcp->syn, ip->daddr, ip->saddr, tcp->dest, ntohs(tcp->source));
		scanlist = scanlist->next;
		id += 1;
	}
}
