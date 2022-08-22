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

/*
** Use response buffer to look inside list of performed scan
** If we find it it means it correspond to one of our scan
** and is ready to be checked
*/
bool	find_scan(void* buffer, struct scan_s *scanlist)
{
	struct iphdr *ip = buffer;
	struct tcphdr *tcp = buffer + sizeof(struct iphdr);
	
//	struct in_addr source;
//	struct in_addr target;

	while (scanlist) {
		if (scanlist->iphdr->daddr == ip->saddr &&
			scanlist->iphdr->saddr == ip->daddr &&
			scanlist->tcphdr->dest == tcp->source &&
			scanlist->tcphdr->source == tcp->dest) {
//			target.s_addr = scanlist->iphdr->daddr;
//			source.s_addr = scanlist->iphdr->saddr;
//			printf("Found scan %s %s %d %d %#x\n", inet_ntoa(source), inet_ntoa(target), ntohs(scanlist->tcphdr->dest), ntohs(scanlist->tcphdr->source), TCP_FLAG(tcp));
//			printf("%#x %#x %#x\n", SYN, ACK, SYNACK);
			return true;
		}

		scanlist = scanlist->next;
	}

	return false;
}
