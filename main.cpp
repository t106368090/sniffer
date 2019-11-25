#include <iostream>
#include <cstring>
#include <pcap.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define cap1
#if defined cap1

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  char buff[1024];
  FILE *fp =fopen("./test.txt","a+");
  sprintf(buff, "%x \n", *packet);
  fwrite(buff, 1, sizeof(packet), fp);
  fclose(fp);
  printf("%x\n",*packet);
  return;
}


int main(int argc, char* argv[])
{
  if(argc<2)
  {
    std::cout << "Type the netword card name" << std::endl;
    return 1;
  }
  pcap_t *p;
  char	errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t	*pdump;
  char cmd[] = "tcp";
  struct bpf_program bpfprog;
  FILE *fp;
  
  p	= pcap_open_live("enp0s3", 65536, 1, 10, errbuf);
  
  if(p	== NULL)
  {
  	fprintf(stderr, "%s\n", errbuf);
  	return	1;
  }
  
  if(pcap_compile(p, &bpfprog, cmd,0 ,0))
  {
  	fprintf(stderr, "%s\n", pcap_geterr(p));
  	return	1;
  }
  /*
  fp =fopen("./test.txt","a");
  if(pcap_dump_fopen(p, fp) == NULL)
  {
  	fprintf(stderr, "%s\n", pcap_geterr(p));
  	pcap_close(p);
  	return	1;
  }
  */
  if(pcap_loop(p, -1, got_packet, NULL)<0)
  {
  	fprintf(stderr, "%s\n", pcap_geterr(p));
  	pcap_dump_close(pdump);
  	pcap_close(p);
  	return	1;
  }
  
  pcap_dump_close(pdump);
  pcap_close(p);
  
  return 0;
} 
#endif

