LDLIBS=-lpcap

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h utils.h main.cpp

utils.o: mac.h ip.h ethhdr.h arphdr.h utils.h utils.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o: mac.h mac.cpp

arp-spoof: main.o utils.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o
