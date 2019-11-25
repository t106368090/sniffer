/*
#include <iostream>
#include "pcap.h"
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <cstring>
 
#define BUFSIZE 1514
 
struct ether_header
{
	unsigned char ether_dhost[6];	
	unsigned char ether_shost[6];	
	unsigned short ether_type;		
};
 
/*******************************回调函数************************************/
/*
void ethernet_protocol_callback(unsigned char *argument,const struct pcap_pkthdr *packet_heaher,const unsigned char *packet_content)
{

	printf("%s \n",packet_content);

}
 
int main(int argc, char *argv[])
{

	char error_content[100];	//出错信息
	pcap_t * pcap_handle;
	unsigned char *mac_string;				
	unsigned short ethernet_type;			//以太网类型
	char *net_interface = NULL;					//接口名字
	struct pcap_pkthdr protocol_header;
	struct ether_header *ethernet_protocol;
	
	net_interface = "enp0s3";//pcap_lookupdev(error_content);
	if(net_interface == NULL)
	{
		perror("pcap_lookupdev");
		exit(-1);
	}
 
	pcap_handle = pcap_open_live(net_interface,BUFSIZE,1,0,error_content);
/*
	if(pcap_loop(pcap_handle,1,ethernet_protocol_callback,NULL) < 0)
	{
		perror("pcap_loop");
	}
	*/

	//pcap_close(pcap_handle);

	
/*
	FILE *file;
	char buffer[128] , buffer1[10] ;
    char state[100] ;
    int length = 0 , i ;

    printf("Please input the statement you want to write : ") ;
    scanf("%s" , state) ;
    length = strlen(state) ;


	if((file = fopen(argv[1], "a")) == NULL)
		{
		    perror("open") ;
		    exit(EXIT_FAILURE) ;
		}
	fwrite(" ",1,1,file);
	fwrite(state, 1, length, file);

    fclose(file) ;


	return 0;
}
*/

