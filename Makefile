# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2008-2023, NVIDIA CORPORATION.  All rights reserved.

# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)

ifdef ALLOW_ARM_FFA_TRANSPORT_AS_MODULE
    HAVE_ARM_FFA = $(CONFIG_ARM_FFA_TRANSPORT)
    KBUILD_CFLAGS += -DALLOW_ARM_FFA_TRANSPORT_AS_MODULE
else
    ifeq ($(CONFIG_ARM_FFA_TRANSPORT),y)
        HAVE_ARM_FFA = $(CONFIG_ARM_FFA_TRANSPORT)
    endif
endif
HAVE_ARM_FFA ?=

obj-m                            := mods.o
mods-y                           := mods_krnl.o
mods-y                           += mods_mem.o
mods-y                           += mods_irq.o
mods-$(CONFIG_PCI)               += mods_pci.o
mods-$(CONFIG_ACPI)              += mods_acpi.o
mods-$(HAVE_ARM_FFA)             += mods_arm_ffa.o
mods-$(CONFIG_DEBUG_FS)          += mods_debugfs.o
mods-$(CONFIG_PPC64)             += mods_ppc64.o
mods-$(CONFIG_TEGRA_IVC)         += mods_bpmpipc.o

# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
endif
