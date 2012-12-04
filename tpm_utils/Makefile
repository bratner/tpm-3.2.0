CFLAGS = -ggdb -w -I../libtpm 

LDLIBS=-L../libtpm -ltpm -lcrypto 

OBJS=bindfile.o chgkeyauth.o chgtpmauth.o clearown.o createkey.o \
disablepubek.o dumpkey.o evictkey.o getpubek.o listkeys.o loadkey.o quote.o \
sealfile.o signfile.o takeown.o tpm_demo.o tpmreset.o unbindfile.o \
unsealfile.o verifyfile.o quote_brat.o verify_quote.o extend.o

PGMS=bindfile chgkeyauth chgtpmauth clearown createkey \
disablepubek dumpkey evictkey getpubek listkeys loadkey quote \
sealfile signfile takeown tpm_demo tpmreset unbindfile \
unsealfile verifyfile quote_brat verify_quote extend

all: $(PGMS)

clean:
	rm -f *.o $(PGMS)

install:
	cp $(PGMS) /usr/local/bin
