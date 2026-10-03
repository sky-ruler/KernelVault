# Out-of-tree Linux kernel driver Makefile for kvault
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all clean help install

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf *.o *.ko *.mod.c *.mod *.order *.symvers .*.cmd .tmp_versions Module.markers modules.order

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

help:
	@echo "kvault kernel module build targets:"
	@echo "  all      - Compile kernel module against active kernel headers"
	@echo "  clean    - Remove build artifacts and temporary files"
	@echo "  install  - Install module into system driver directory"
