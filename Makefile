obj-m += vhost-9p.o
obj-m += 9pnet_local.o

#vhost-9p-objs := vhost-9p.o
9pnet_local-objs := trans_local.o protocol.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
