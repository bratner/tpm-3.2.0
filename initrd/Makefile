# Makefile for modified initrd.
# Rebuilds a TPM/EVM/SLIM enabled initrd for the current running kernel.
# or for a kernel specified in the KVER variable...
# The tpm, evm and slim kernel modules should already be installed.
# The loadkernkey program should already be compiled

KVER= $(shell uname -r)
#KVER=2.6.20-rc4-mm1

BOBJS= ../kernkey/loadkernkey 

initrd.new: $(KOBJS) $(BOBJS) $(ROBJS) $(EOBJS)
	#unpack
	cp /boot/initrd-$(KVER).img initrd.old.img
	zcat initrd.old.img >initrd.old.cpio
	/bin/rm -rf ./root
	mkdir root
	cat initrd.old.cpio | (cd root;cpio --quiet -i)
	#addfiles:
	cp $(BOBJS) ./root/bin
	cp ./root/init init.orig
	#add tcfl commands to init script
	./mkinit
	cp ./init   ./root/init
	#repack:
	(cd root; find . |cpio --quiet -c -o ) > initrd.new.cpio
	gzip -9 < initrd.new.cpio > initrd-$(KVER).new.img

install:
	cp initrd-$(KVER).new.img /boot

clean:
	/bin/rm -rf initrd*.new.img initrd.new.cpio initrd.old.img \
	initrd.old.cpio root init init.orig
