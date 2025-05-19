obj-m += the_block-device-snapshot-service.o
the_block-device-snapshot-service-objs += block-device-snapshot-service.o lib/scth.o

A = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount:
	mkdir /snapshot
	insmod the_block-device-snapshot-service.ko the_syscall_table=$(A)
	
unmount:
	rm -rf /snapshot
	rmmod the_block-device-snapshot-service
