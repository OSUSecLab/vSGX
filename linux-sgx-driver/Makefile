isgx-y := \
	sgx_main.o \
	sgx_page_cache.o \
	sgx_ioctl.o \
	sgx_vma.o \
	sgx_util.o\
	sgx_encl.o \
	sgx_encl2.o
obj-m += isgx.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install: default
	$(MAKE) INSTALL_MOD_DIR=kernel/drivers/intel/sgx -C $(KDIR) M=$(PWD) modules_install
	depmod -A
	sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd *.mod
