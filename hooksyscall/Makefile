obj-m += hooksys.o

LINUX_KERNEL_PATH = /lib/modules/$(shell uname -r)/build
CURRENT_PATH = $(shell pwd)

all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean



