INCS = -I../libtpm
LIBS = ../libtpm/libtpm.a -l crypto

# defining USERTEST adds lots of debugging
#CC = gcc -Wall -static -g -O2 -DUSERTEST $(INCS)
CC = gcc -Wall -static -s -O2 $(INCS)

default: init_tpm  loadkernkey

loadkernkey: loadkernkey.o 
	$(CC) -o loadkernkey loadkernkey.o $(LIBS)

init_tpm: init_tpm.o 
	$(CC) -o init_tpm init_tpm.o $(LIBS)

install:
	cp loadkernkey /usr/local/bin
	cp init_tpm /usr/local/bin

clean:
	rm -f *.o loadkernkey init_tpm
