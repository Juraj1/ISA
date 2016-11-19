BINARY=myL2monitor
CC=g++
CFLAGS=-std=c++11 -Wall -pedantic -ggdb
OBJFILES=	sniffer.o\
					main.o
LINKWITH=-lpcap -lpthread

${BINARY}:${OBJFILES}
	${CC} ${OBJFILES} ${LINKWITH} -o  ${BINARY}
	mv *.o objfiles

sniffer.o:src/sniffer.cpp
	${CC} ${CFLAGS} src/sniffer.cpp -c

main.o:src/main.cpp
	${CC} ${CFLAGS} src/main.cpp -c




clean:
	rm -rf objfiles/*.o

purge:clean
	rm -rf ${BINARY}

pack: purge
	tar -cvf xzahra22.tar src objfiles doc Makefile
