obj-m += vhost-9p-lkm.o

vhost-9p-lkm-objs := vhost-9p.o 9p-ops.o protocol.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
