obj-m += emusgx-module.o
emusgx-module-objs = module.o wrapper.o traps.o enclu.o fault.o encls.o cross_vm.o \
	irq_handler.o crypto.o dispatcher.o response.o sender.o switchless_sync.o \
	aex.o local_management.o worker_threads.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:	all
	sudo insmod emusgx-module.ko
