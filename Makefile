.PHONY: all clean

all : Aimazing 

Aimazing: 
	@g++ main.cpp ./libpcap.a -o Aimazing -I ./libpcap-1.9.1/ 

clean : 
	-rm -f *.o Aimazing test.txt
	
