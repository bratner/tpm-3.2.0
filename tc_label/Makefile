CFLAGS= -Wall -O2

tc_label: tc_label.o slim.o
	$(CC) -o tc_label tc_label.o slim.o -lcrypto

clean:
	rm -f *.o tc_label

install:
	cp tc_label /usr/local/bin
