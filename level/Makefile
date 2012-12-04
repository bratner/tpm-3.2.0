CFLAGS= -Wall -O

level: level.o
	cc -o level level.o -lcrypto

clean :
	rm *.o level

install:
	mkdir -p /usr/local/bin
	cp level /usr/local/bin/level
