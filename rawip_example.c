/*
 * rawip_example.c
 *
 *  Created on: May 4, 2016
 *      Author: jiaziyi
 */


#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <errno.h>
#include "header.h"

#define SRC_IP  "129.104.237.150" //set your source ip here. It can be a fake one
#define SRC_PORT 54321 //set the source port here. It can be a fake one

#define DEST_IP "127.0.0.2" //set your destination ip here
#define DEST_PORT 3000 //set the destination port here
#define TEST_STRING "test data" //a test string as packet payload

int main(int argc, char *argv[])
{
	char source_ip[] = SRC_IP;
	char dest_ip[] = DEST_IP;


	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	printf("fd est %d\n", fd);
	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

	char packet[65536], *data;
	char data_string[] = TEST_STRING;
	memset(packet, 0, 65536);

	//IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//UDP header pointer
	struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_udp_header psh; //pseudo header

	//data section pointer
	data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

	//fill the data section
	strncpy(data, data_string, strlen(data_string));

	//fill the IP header here
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
	iph->id=htonl(16670); // I chose an ID randomly using the logfile of the previous exercise
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol =17;
	iph->check=checksum((unsigned short *)packet, sizeof (struct iphdr));
	iph->saddr = inet_addr ( source_ip );	
	iph->daddr =  inet_addr (dest_ip);

	//fill the UDP header
	/*
    struct pseudo_udp_header
    {
	u_int32_t source_addres
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
     };
	*/
	udph->source= htons (SRC_PORT);
	udph->dest = htons (DEST_PORT);
	udph->len = htons(8 + strlen(data));	//tcp header size
	udph->check = 0;	//filled by pseudo header below



	psh.source_address = inet_addr( source_ip );
	psh.dest_address = inet_addr (dest_ip);
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );


	int psize = sizeof(struct pseudo_udp_header) + sizeof(struct udphdr) + strlen(data);
	char* pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_udp_header));
	memcpy(pseudogram + sizeof(struct pseudo_udp_header) , udph , sizeof(struct udphdr) + strlen(data));
	udph->check=checksum((unsigned short*)pseudogram,psize);
	
	
	//send the packet
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
   // inet_aton(dest_ip, &dest.sin_addr);
    dest.sin_addr.s_addr = inet_addr (dest_ip);
	dest.sin_port = htons(DEST_PORT);

		
	int sent=sendto(fd, packet, iph->tot_len , MSG_CONFIRM, (struct sockaddr*) &dest,  sizeof(dest));
	 if (sent<0)
    {
        fprintf(stderr, "Could not send: %s\n", strerror(errno));
    } 
	else
		{
			printf ("our packet is sent and here is its length: %d \n" , iph->tot_len);
		}

	
	return 0;

}
