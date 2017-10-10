all: arp_shoot
arp_shoot: main.o netfunc.o
	g++ --std=c++11 -O2 -oarp_shoot main.o netfunc.o -lpcap

main.o: main.cpp netfunc.h
	g++ --std=c++11 -O2 -c -omain.o main.cpp

netfunc.o: netfunc.cpp netfunc.h
	g++ --std=c++11 -O2 -c -onetfunc.o netfunc.cpp

clean:
	rm -f *.o
	rm -f arp_shoot
