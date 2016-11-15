BINARY=myL2monitor
CC=g++
CFLAGS=-std=c++11 -Wall -pedantic -ggdb
OBJFILES=	sniffer.o\
					main.o


${BINARY}:${OBJFILES}
	${CC} ${OBJFILES} -lpcap -o  ${BINARY}
	mv *.o objfiles

main.o:src/main.cpp
	${CC} ${CFLAGS} src/main.cpp -c

sniffer.o:src/sniffer.cpp
	${CC} ${CFLAGS} src/sniffer.cpp -c



clean:
	rm -rf objfiles/*.o

purge:clean
	rm -rf ${BINARY}
