// SPDX-License-Identifier: GPL-2.0-only
/* SPDX-FileCopyrightText: Copyright (c) 2008-2026, NVIDIA CORPORATION.  All rights reserved. */

#include "mods_internal.h"

#include <linux/device.h>
#if defined(MODS_HAS_DMA_OPS)
#include <linux/dma-mapping.h>
#endif
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/pci.h>
#if KERNEL_VERSION(2, 32, 0) <= MODS_KERNEL_VERSION
#include <linux/pm_runtime.h>
#endif
#if KERNEL_VERSION(3, 19, 0) <= MODS_KERNEL_VERSION
#include <linux/property.h>
#endif

/* Address in config space is 8bit for base caps and 12bit for extended caps */
#define MODS_MAX_PCI_CFG_ADDR 0xFFFU

int mods_is_pci_dev(struct pci_dev        *dev,
		    struct mods_pci_dev_2 *pcidev)
{
	unsigned int devfn = PCI_DEVFN(pcidev->device, pcidev->function);

	return dev &&
	       pci_domain_nr(dev->bus) == pcidev->domain &&
	       dev->bus->number == pcidev->bus &&
	       dev->devfn == devfn;
}

int mods_find_pci_dev(struct mods_client    *client,
		      struct mods_pci_dev_2 *pcidev,
		      struct pci_dev	   **retdev)
{
	struct pci_dev *dev;
	int             err;

	if (unlikely(mutex_lock_interruptible(&client->mtx)))
		return -EINTR;

	dev = client->cached_dev;

	if (mods_is_pci_dev(dev, pcidev)) {
		*retdev = pci_dev_get(dev);
		mutex_unlock(&client->mtx);
		return OK;
	}

	mutex_unlock(&client->mtx);

	dev = NULL;

	dev = pci_get_domain_bus_and_slot(pcidev->domain,
					  pcidev->bus,
					  PCI_DEVFN(pcidev->device,
						    pcidev->function));

	if (dev) {
		if (unlikely(mutex_lock_interruptible(&client->mtx))) {
			pci_dev_put(dev);
			return -EINTR;
		}

		if (dev != client->cached_dev) {
			pci_dev_put(client->cached_dev);
			client->cached_dev = pci_dev_get(dev);
		}

		mutex_unlock(&client->mtx);

		err = OK;
	} else
		err = -ENODEV;

	*retdev = dev;
	return err;
}

static int find_pci_dev_impl(struct mods_client            *client,
			     struct MODS_FIND_PCI_DEVICE_2 *p,
			     int                            enum_non_zero_dom)
{
	struct pci_dev *dev   = NULL;
	int             index = -1;

	LOG_ENT();

	if (p->index > 0xFFFFU) {
		cl_error("invalid device index %u\n", p->index);
		LOG_EXT();
		return -EINVAL;
	}

	cl_debug(DEBUG_PCI,
		 "find pci dev %04x:%04x, index %u\n",
		 p->vendor_id,
		 p->device_id,
		 p->index);

	do {
		dev = pci_get_device(p->vendor_id, p->device_id, dev);
		if (!dev) {
			LOG_EXT();
			return -EINVAL;
		}

		if (enum_non_zero_dom || !pci_domain_nr(dev->bus))
			++index;
	} while (index < (int)(p->index));

	p->pci_device.domain   = pci_domain_nr(dev->bus);
	p->pci_device.bus      = dev->bus->number;
	p->pci_device.device   = PCI_SLOT(dev->devfn);
	p->pci_device.function = PCI_FUNC(dev->devfn);

	pci_dev_put(dev);
	LOG_EXT();
	return OK;
}

int esc_mods_find_pci_dev_2(struct mods_client            *client,
			    struct MODS_FIND_PCI_DEVICE_2 *p)
{
	return find_pci_dev_impl(client, p, 1);
}

int esc_mods_find_pci_dev(struct mods_client          *client,
			  struct MODS_FIND_PCI_DEVICE *p)
{
	struct MODS_FIND_PCI_DEVICE_2 p2;
	int                           err;

	p2.device_id = p->device_id;
	p2.vendor_id = p->vendor_id;
	p2.index     = p->index;

	err = find_pci_dev_impl(client, &p2, 0);

	if (!err) {
		p->bus_number      = p2.pci_device.bus;
		p->device_number   = p2.pci_device.device;
		p->function_number = p2.pci_device.function;
	}

	return err;
}

static int mods_find_pci_class_code(struct mods_client                *client,
				    struct MODS_FIND_PCI_CLASS_CODE_2 *p,
				    int enum_non_zero_dom)
{
	struct pci_dev *dev   = NULL;
	int             index = -1;

	LOG_ENT();

	if (p->index > 0xFFFFU) {
		cl_error("invalid device index %u\n", p->index);
		LOG_EXT();
		return -EINVAL;
	}

	cl_debug(DEBUG_PCI,
		 "find pci class code %04x, index %u\n",
		 p->class_code,
		 p->index);

	do {
		dev = pci_get_class(p->class_code, dev);
		if (!dev) {
			LOG_EXT();
			return -EINVAL;
		}

		if (enum_non_zero_dom || !pci_domain_nr(dev->bus))
			++index;
	} while (index < (int)(p->index));

	p->pci_device.domain   = pci_domain_nr(dev->bus);
	p->pci_device.bus      = dev->bus->number;
	p->pci_device.device   = PCI_SLOT(dev->devfn);
	p->pci_device.function = PCI_FUNC(dev->devfn);

	pci_dev_put(dev);
	LOG_EXT();
	return OK;
}

int esc_mods_find_pci_class_code_2(struct mods_client                *client,
				   struct MODS_FIND_PCI_CLASS_CODE_2 *p)
{
	return mods_find_pci_class_code(client, p, 1);
}

int esc_mods_find_pci_class_code(struct mods_client              *client,
				 struct MODS_FIND_PCI_CLASS_CODE *p)
{
	struct MODS_FIND_PCI_CLASS_CODE_2 p2;
	int                               err;

	p2.class_code = p->class_code;
	p2.index      = p->index;

	err = mods_find_pci_class_code(client, &p2, 0);

	if (!err) {
		p->bus_number      = p2.pci_device.bus;
		p->device_number   = p2.pci_device.device;
		p->function_number = p2.pci_device.function;
	}

	return err;
}

static int pci_bar_index_to_resource(struct pci_dev *dev,
				     u32             bar_index,
				     unsigned int   *bar_resource_offset)
{
	unsigned int i;

	*bar_resource_offset = 0;
	for (i = 0; i < bar_index; i++) {
		if (unlikely(*bar_resource_offset >= PCI_NUM_RESOURCES))
			return -EINVAL;

		if (pci_resource_flags(dev, *bar_resource_offset) &
		    IORESOURCE_MEM_64)
			*bar_resource_offset += 2;
		else
			*bar_resource_offset += 1;
	}

	if (unlikely(*bar_resource_offset >= PCI_NUM_RESOURCES))
		return -EINVAL;

	return 0;
}

int esc_mods_pci_get_bar_info_2(struct mods_client             *client,
				struct MODS_PCI_GET_BAR_INFO_2 *p)
{
	struct pci_dev *dev;
	unsigned int    bar_resource_offset;
	int             err;

	LOG_ENT();

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		LOG_EXT();
		return err;
	}

	cl_debug(DEBUG_PCI,
		 "pci get bar info dev %04x:%02x:%02x:%x, bar index %u\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function,
		 p->bar_index);

	err = pci_bar_index_to_resource(dev, p->bar_index, &bar_resource_offset);
	if (unlikely(err)) {
		cl_error("invalid pci bar index %u\n", p->bar_index);
		goto error;
	}

	p->base_address = pci_resource_start(dev, bar_resource_offset);
	p->bar_size     = pci_resource_len(dev, bar_resource_offset);

error:
	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

int esc_mods_pci_get_bar_info(struct mods_client           *client,
			      struct MODS_PCI_GET_BAR_INFO *p)
{
	int err;
	struct MODS_PCI_GET_BAR_INFO_2 get_bar_info = { {0} };

	get_bar_info.pci_device.domain   = 0;
	get_bar_info.pci_device.bus      = p->pci_device.bus;
	get_bar_info.pci_device.device   = p->pci_device.device;
	get_bar_info.pci_device.function = p->pci_device.function;
	get_bar_info.bar_index           = p->bar_index;

	err = esc_mods_pci_get_bar_info_2(client, &get_bar_info);

	if (likely(!err)) {
		p->base_address = get_bar_info.base_address;
		p->bar_size     = get_bar_info.bar_size;
	}

	return err;
}

int esc_mods_pci_get_irq_2(struct mods_client        *client,
			   struct MODS_PCI_GET_IRQ_2 *p)
{
	struct pci_dev *dev;
	int err;

	LOG_ENT();

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		LOG_EXT();
		return err;
	}

	cl_debug(DEBUG_PCI,
		 "pci get irq dev %04x:%02x:%02x:%x irq=%u\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function,
		 dev->irq);

	p->irq = dev->irq;

	pci_dev_put(dev);
	LOG_EXT();
	return OK;
}

int esc_mods_pci_get_irq(struct mods_client      *client,
			 struct MODS_PCI_GET_IRQ *p)
{
	int err;
	struct MODS_PCI_GET_IRQ_2 get_irq = { {0} };

	get_irq.pci_device.domain   = 0;
	get_irq.pci_device.bus	    = p->pci_device.bus;
	get_irq.pci_device.device   = p->pci_device.device;
	get_irq.pci_device.function = p->pci_device.function;

	err = esc_mods_pci_get_irq_2(client, &get_irq);

	if (likely(!err))
		p->irq = get_irq.irq;

	return err;
}

int esc_mods_pci_read_2(struct mods_client *client, struct MODS_PCI_READ_2 *p)
{
	struct pci_dev *dev;
	int err;
	int dbdf;

	LOG_ENT();

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		LOG_EXT();
		return err;
	}

	if (p->address > MODS_MAX_PCI_CFG_ADDR) {
		cl_error("invalid pci config space address 0x%x\n", p->address);
		pci_dev_put(dev);
		LOG_EXT();
		return -EINVAL;
	}

	p->data = 0;
	switch (p->data_size) {
	case 1: {
			u8 value;

			pci_read_config_byte(dev, p->address, &value);
			p->data = value;
		}
		break;
	case 2: {
			u16 value;

			pci_read_config_word(dev, p->address, &value);
			p->data = value;
		}
		break;
	case 4:
		pci_read_config_dword(dev, p->address, (u32 *) &p->data);
		break;
	default:
		err = -EINVAL;
		break;
	}

	cl_debug(DEBUG_PCI | DEBUG_DETAILED,
		 "pci read dev %04x:%02x:%02x.%x, addr 0x%04x, size %u, data 0x%x\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function,
		 p->address,
		 p->data_size,
		 p->data);

	dbdf = (int)(((u32)p->pci_device.domain << 16) |
		     ((u32)(p->pci_device.bus & 0xFFU) << 8) |
		     (u32)(p->pci_device.device & 0xFFU));

	/* Usually one of the first reads from PCI config space occurs
	 * at address 0 and or 2 to read PCI device vendor/id.
	 * If this reads all Fs, the device probably fell off the bus.
	 */
	if (p->address <= 4 && (p->data == ~0U || p->data == 0xFFFFU)) {
		if (dbdf != atomic_read(&client->last_bad_dbdf))
			cl_warn("pci read dev %04x:%02x:%02x.%x, addr 0x%04x, size %u, data 0x%x\n",
				p->pci_device.domain,
				p->pci_device.bus,
				p->pci_device.device,
				p->pci_device.function,
				p->address,
				p->data_size,
				p->data);
		atomic_set(&client->last_bad_dbdf, dbdf);
	} else if (dbdf == atomic_read(&client->last_bad_dbdf))
		atomic_set(&client->last_bad_dbdf, -1);

	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

int esc_mods_pci_read(struct mods_client *client, struct MODS_PCI_READ *p)
{
	int err;
	struct MODS_PCI_READ_2 pci_read = { {0} };

	if (p->bus_number > 0xFFU) {
		cl_error("invalid bus number 0x%x\n", p->bus_number);
		return -EINVAL;
	}
	if (p->device_number > 0xFFU) {
		cl_error("invalid device number 0x%x\n", p->device_number);
		return -EINVAL;
	}
	if (p->function_number > 0xFU) {
		cl_error("invalid function number 0x%x\n", p->function_number);
		return -EINVAL;
	}

	pci_read.pci_device.domain	= 0;
	pci_read.pci_device.bus		= p->bus_number;
	pci_read.pci_device.device	= p->device_number;
	pci_read.pci_device.function	= p->function_number;
	pci_read.address		= p->address;
	pci_read.data_size		= p->data_size;

	err = esc_mods_pci_read_2(client, &pci_read);

	if (likely(!err))
		p->data = pci_read.data;

	return err;
}

int esc_mods_pci_write_2(struct mods_client *client, struct MODS_PCI_WRITE_2 *p)
{
	struct pci_dev *dev;
	int err;

	LOG_ENT();

	cl_debug(DEBUG_PCI | DEBUG_DETAILED,
		 "pci write dev %04x:%02x:%02x.%x, addr 0x%04x, size %u, data 0x%x\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function,
		 p->address,
		 p->data_size,
		 p->data);

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 p->pci_device.domain,
				 p->pci_device.bus,
				 p->pci_device.device,
				 p->pci_device.function);
		LOG_EXT();
		return err;
	}

	if (p->address > MODS_MAX_PCI_CFG_ADDR) {
		cl_error("invalid pci config space address 0x%x\n", p->address);
		pci_dev_put(dev);
		LOG_EXT();
		return -EINVAL;
	}

	switch (p->data_size) {
	case 1:
		if (p->data > 0xFFU) {
			cl_error("invalid byte data 0x%x\n", p->data);
			err = -EINVAL;
		} else
			pci_write_config_byte(dev, p->address, p->data);
		break;
	case 2:
		if (p->data > 0xFFFFU) {
			cl_error("invalid word data 0x%x\n", p->data);
			err = -EINVAL;
		} else
			pci_write_config_word(dev, p->address, p->data);
		break;
	case 4:
		pci_write_config_dword(dev, p->address, p->data);
		break;
	default:
		cl_error("invalid data size %u\n", p->data_size);
		err = -EINVAL;
		break;
	}

	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

int esc_mods_pci_write(struct mods_client    *client,
		       struct MODS_PCI_WRITE *p)
{
	struct MODS_PCI_WRITE_2 pci_write = { {0} };

	if (p->bus_number > 0xFFU) {
		cl_error("invalid bus number 0x%x\n", p->bus_number);
		return -EINVAL;
	}
	if (p->device_number > 0xFFU) {
		cl_error("invalid device number 0x%x\n", p->device_number);
		return -EINVAL;
	}
	if (p->function_number > 0xFU) {
		cl_error("invalid function number 0x%x\n", p->function_number);
		return -EINVAL;
	}

	pci_write.pci_device.domain	= 0;
	pci_write.pci_device.bus	= p->bus_number;
	pci_write.pci_device.device	= p->device_number;
	pci_write.pci_device.function	= p->function_number;
	pci_write.address		= p->address;
	pci_write.data			= p->data;
	pci_write.data_size		= p->data_size;

	return esc_mods_pci_write_2(client, &pci_write);
}

int esc_mods_pci_bus_add_dev(struct mods_client              *client,
			     struct MODS_PCI_BUS_ADD_DEVICES *scan)
{
	struct MODS_PCI_BUS_RESCAN rescan = { 0, 0 };

	if (scan->bus > 0xFFU) {
		cl_error("invalid bus number 0x%x\n", scan->bus);
		return -EINVAL;
	}

	rescan.bus = (u16)scan->bus;

	return esc_mods_pci_bus_rescan(client, &rescan);
}

int esc_mods_pci_bus_rescan(struct mods_client         *client,
			    struct MODS_PCI_BUS_RESCAN *rescan)
{
	struct pci_bus *bus;
	int    err = OK;

	LOG_ENT();

	cl_info("scanning pci bus %04x:%02x\n", rescan->domain, rescan->bus);

	bus = pci_find_bus(rescan->domain, rescan->bus);

	if (likely(bus)) {
#ifndef MODS_HASNT_PCI_LOCK_RESCAN_REMOVE
		pci_lock_rescan_remove();
#endif
		pci_rescan_bus(bus);
#ifndef MODS_HASNT_PCI_LOCK_RESCAN_REMOVE
		pci_unlock_rescan_remove();
#endif
	} else {
		cl_error("bus %04x:%02x not found\n",
			 rescan->domain,
			 rescan->bus);
		err = -EINVAL;
	}

	LOG_EXT();

	return err;
}

int esc_mods_pci_bus_remove_dev(struct mods_client             *client,
				struct MODS_PCI_BUS_REMOVE_DEV *p)
{
#if !defined(MODS_HASNT_PCI_BUS_REMOVE_DEV)
	struct pci_dev *dev;
	int err;

	LOG_ENT();

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error(
				"pci_remove cannot find dev %04x:%02x:%02x.%x\n",
				p->pci_device.domain,
				p->pci_device.bus,
				p->pci_device.device,
				p->pci_device.function);
		LOG_EXT();
		return err;
	}

	cl_debug(DEBUG_PCI,
		 "pci remove on dev %04x:%02x:%02x.%x\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function);

	pci_stop_and_remove_bus_device(dev);
	pci_dev_put(dev);
	LOG_EXT();
	return err;
#else
	return -EINVAL;
#endif
}

/************************
 * PIO ESCAPE FUNCTIONS *
 ************************/

int esc_mods_pio_read(struct mods_client *client, struct MODS_PIO_READ *p)
{
	LOG_ENT();
	switch (p->data_size) {
	case 1:
		p->data = inb(p->port);
		break;
	case 2:
		p->data = inw(p->port);
		break;
	case 4:
		p->data = inl(p->port);
		break;
	default:
		return -EINVAL;
	}
	LOG_EXT();
	return OK;
}

int esc_mods_pio_write(struct mods_client *client, struct MODS_PIO_WRITE *p)
{
	int err = OK;

	LOG_ENT();

	switch (p->data_size) {
	case 1:
		if (p->data > 0xFFU) {
			cl_error("invalid byte data 0x%x\n", p->data);
			err = -EINVAL;
		} else
			outb(p->data, p->port);
		break;
	case 2:
		if (p->data > 0xFFFFU) {
			cl_error("invalid word data 0x%x\n", p->data);
			err = -EINVAL;
		} else
			outw(p->data, p->port);
		break;
	case 4:
		outl(p->data, p->port);
		break;
	default:
		cl_error("invalid data size %u\n", p->data_size);
		err = -EINVAL;
	}

	LOG_EXT();
	return err;
}

int esc_mods_device_numa_info_3(struct mods_client             *client,
				struct MODS_DEVICE_NUMA_INFO_3 *p)
{
	struct pci_dev *dev;
	int err;

	LOG_ENT();

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 p->pci_device.domain,
				 p->pci_device.bus,
				 p->pci_device.device,
				 p->pci_device.function);
		LOG_EXT();
		return err;
	}

	p->node = dev_to_node(&dev->dev);
	if (p->node != -1) {
		u32                  first_offset = ~0U;
		unsigned int         i;
		const unsigned long *maskp;

		maskp = cpumask_bits(cpumask_of_node(p->node));

		memset(&p->node_cpu_mask, 0, sizeof(p->node_cpu_mask));

		for (i = 0; i < nr_cpumask_bits; i += 32) {

			const u32 word     = i / BITS_PER_LONG;
			const u32 bit      = i % BITS_PER_LONG;
			const u32 cur_mask = (u32)(maskp[word] >> bit);
			u32       mask_idx;

			if (first_offset == ~0U) {
				if (cur_mask) {
					first_offset             = i / 32;
					p->first_cpu_mask_offset = first_offset;
				} else
					continue;
			}

			mask_idx = (i / 32) - first_offset;

			if (cur_mask && mask_idx >= MAX_CPU_MASKS_3) {

				cl_error("too many CPUs (%d) for mask bits\n",
					 nr_cpumask_bits);
				pci_dev_put(dev);
				LOG_EXT();
				return -EINVAL;
			}

			if (mask_idx < MAX_CPU_MASKS_3)
				p->node_cpu_mask[mask_idx] = cur_mask;
		}

		if (first_offset == ~0U)
			p->first_cpu_mask_offset = 0;
	}
	p->node_count = num_possible_nodes();
	p->cpu_count  = num_possible_cpus();

	pci_dev_put(dev);
	LOG_EXT();
	return OK;
}

int esc_mods_device_numa_info_2(struct mods_client             *client,
				struct MODS_DEVICE_NUMA_INFO_2 *p)
{
	int err;
	struct MODS_DEVICE_NUMA_INFO_3 numa_info = { {0} };

	numa_info.pci_device = p->pci_device;

	err = esc_mods_device_numa_info_3(client, &numa_info);

	if (likely(!err)) {
		int i;

		p->node	      = numa_info.node;
		p->node_count = numa_info.node_count;
		p->cpu_count  = numa_info.cpu_count;

		memset(&p->node_cpu_mask, 0, sizeof(p->node_cpu_mask));

		for (i = 0; i < MAX_CPU_MASKS_3; i++) {

			const u32 cur_mask = numa_info.node_cpu_mask[i];
			const u32 dst      = i +
					     numa_info.first_cpu_mask_offset;

			if (cur_mask && dst >= MAX_CPU_MASKS) {
				cl_error("too many CPUs (%d) for mask bits\n",
					 nr_cpumask_bits);
				err = -EINVAL;
				break;
			}

			if (dst < MAX_CPU_MASKS)
				p->node_cpu_mask[dst]
					= numa_info.node_cpu_mask[i];
		}
	}

	return err;
}

int esc_mods_device_numa_info(struct mods_client           *client,
			      struct MODS_DEVICE_NUMA_INFO *p)
{
	int err;
	struct MODS_DEVICE_NUMA_INFO_3 numa_info = { {0} };

	numa_info.pci_device.domain    = 0;
	numa_info.pci_device.bus       = p->pci_device.bus;
	numa_info.pci_device.device    = p->pci_device.device;
	numa_info.pci_device.function  = p->pci_device.function;

	err = esc_mods_device_numa_info_3(client, &numa_info);

	if (likely(!err)) {
		int i;

		p->node	      = numa_info.node;
		p->node_count = numa_info.node_count;
		p->cpu_count  = numa_info.cpu_count;

		memset(&p->node_cpu_mask, 0, sizeof(p->node_cpu_mask));

		for (i = 0; i < MAX_CPU_MASKS_3; i++) {

			const u32 cur_mask = numa_info.node_cpu_mask[i];
			const u32 dst      = i +
					     numa_info.first_cpu_mask_offset;

			if (cur_mask && dst >= MAX_CPU_MASKS) {
				cl_error("too many CPUs (%d) for mask bits\n",
					 nr_cpumask_bits);
				err = -EINVAL;
				break;
			}

			if (dst < MAX_CPU_MASKS)
				p->node_cpu_mask[dst]
					= numa_info.node_cpu_mask[i];
		}
	}

	return err;
}

int esc_mods_get_iommu_state(struct mods_client          *client,
			     struct MODS_GET_IOMMU_STATE *state)
{
	int err = esc_mods_get_iommu_state_2(client, state);

	if (!err)
		state->state = (state->state == MODS_SWIOTLB_DISABLED) ? 1 : 0;

	return err;
}

int esc_mods_get_iommu_state_2(struct mods_client          *client,
			       struct MODS_GET_IOMMU_STATE *state)
{
#if !defined(CONFIG_SWIOTLB)
	state->state = MODS_SWIOTLB_DISABLED;
#elif defined(MODS_HAS_DMA_OPS)

	const struct dma_map_ops *ops;
	struct pci_dev           *dev;
	int                       err;

	LOG_ENT();

	err = mods_find_pci_dev(client, &state->pci_device, &dev);
	if (unlikely(err)) {
		LOG_EXT();
		return err;
	}

	ops = get_dma_ops(&dev->dev);

	state->state = ops->map_sg != swiotlb_map_sg_attrs
		       ? MODS_SWIOTLB_DISABLED : MODS_SWIOTLB_ACTIVE;

	pci_dev_put(dev);
	LOG_EXT();

#else
	/* No way to detect it */
	state->state = MODS_SWIOTLB_INDETERMINATE;
#endif
	return OK;
}

int esc_mods_pci_set_dma_mask(struct mods_client       *client,
			      struct MODS_PCI_DMA_MASK *dma_mask)
{
	int             err;
	struct pci_dev *dev;
	u64             mask;

	LOG_ENT();

	if (unlikely(dma_mask->num_bits > 64)) {
		cl_error("num_bits=%u exceeds 64\n",
			 dma_mask->num_bits);
		LOG_EXT();
		return -EINVAL;
	}

	err = mods_find_pci_dev(client, &dma_mask->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 dma_mask->pci_device.domain,
				 dma_mask->pci_device.bus,
				 dma_mask->pci_device.device,
				 dma_mask->pci_device.function);
		LOG_EXT();
		return err;
	}

	mask = dma_mask->num_bits == 64 ? ~0ULL : (1ULL<<dma_mask->num_bits)-1;

	err = dma_set_mask(&dev->dev, mask);
	if (err) {
		cl_error(
			"failed to set dma mask 0x%llx (%u) for dev %04x:%02x:%02x.%x\n",
			mask,
			dma_mask->num_bits,
			dma_mask->pci_device.domain,
			dma_mask->pci_device.bus,
			dma_mask->pci_device.device,
			dma_mask->pci_device.function);
	} else {
		err = dma_set_coherent_mask(&dev->dev, mask);
		if (err)
			cl_error(
				"failed to set consistent dma mask 0x%llx (%u) for dev %04x:%02x:%02x.%x\n",
				mask,
				dma_mask->num_bits,
				dma_mask->pci_device.domain,
				dma_mask->pci_device.bus,
				dma_mask->pci_device.device,
				dma_mask->pci_device.function);
	}

	if (!err)
		cl_info("set dma mask %u for dev %04x:%02x:%02x.%x\n",
			dma_mask->num_bits,
			dma_mask->pci_device.domain,
			dma_mask->pci_device.bus,
			dma_mask->pci_device.device,
			dma_mask->pci_device.function);

	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

static int check_flr(struct pci_dev *dev)
{
	int cap_pos;
	u32 cap;

#if KERNEL_VERSION(4, 12, 0) <= MODS_KERNEL_VERSION
	if (dev->dev_flags & PCI_DEV_FLAGS_NO_FLR_RESET)
		return -ENOTTY;
#endif

	cap_pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!cap_pos)
		return -ENOTTY;

	pci_read_config_dword(dev, cap_pos + PCI_EXP_DEVCAP, &cap);
	if (!(cap & PCI_EXP_DEVCAP_FLR))
		return -ENOTTY;

	return 0;
}


#ifdef MODS_HAS_PCI_RESET_BUS
static int pci_bus_pm_get_all(struct mods_client *client,
			      struct pci_bus *bus)
{
	struct pci_dev *dev;
	int             err = 0;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		err = pm_runtime_get_sync(&dev->dev);
		if (err < 0) {
			pm_runtime_put_noidle(&dev->dev);
			goto error;
		}
	}
	return 0;

error:
	cl_error("pm_runtime resume failed (%d) on dev %04x:%02x:%02x.%x\n",
		 err,
		 pci_domain_nr(dev->bus),
		 dev->bus->number,
		 PCI_SLOT(dev->devfn),
		 PCI_FUNC(dev->devfn));
	list_for_each_entry_continue_reverse(dev, &bus->devices, bus_list) {
		pm_runtime_put(&dev->dev);
	}
	return err;
}

static void pci_bus_pm_put_all(struct pci_bus *bus)
{
	struct pci_dev *dev;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		pm_runtime_put(&dev->dev);
	}
}

int esc_mods_pci_reset_bus(struct mods_client    *client,
			   struct mods_pci_dev_2 *pcidev)
{
	struct pci_dev *dev;
	struct pci_bus *bus;
	int             err = 0;

	LOG_ENT();

	err = mods_find_pci_dev(client, pcidev, &dev);

	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 pcidev->domain,
				 pcidev->bus,
				 pcidev->device,
				 pcidev->function);
		LOG_EXT();
		return err;
	}

	bus = dev->bus;
	if (unlikely(!bus || !bus->self)) {
		cl_error("dev %04x:%02x:%02x.%x has no upstream bridge; cannot issue SBR\n",
			 pcidev->domain,
			 pcidev->bus,
			 pcidev->device,
			 pcidev->function);
		err = -ENOTTY;
		goto error;
	}

	err = pci_bus_pm_get_all(client, bus);
	if (err < 0)
		goto error;

	err = pci_reset_bus(dev);

	pci_bus_pm_put_all(bus);

	if (unlikely(err))
		cl_error("pci_reset_bus failed on dev %04x:%02x:%02x.%x\n",
			 pcidev->domain,
			 pcidev->bus,
			 pcidev->device,
			 pcidev->function);
	else
		cl_info("pci_reset_bus succeeded on dev %04x:%02x:%02x.%x\n",
			pcidev->domain,
			pcidev->bus,
			pcidev->device,
			pcidev->function);

error:
	pci_dev_put(dev);
	LOG_EXT();
	return err;
}
#endif

int esc_mods_pci_reset_function(struct mods_client    *client,
				struct mods_pci_dev_2 *pcidev)
{
	struct pci_dev *dev;
	int             err;

	LOG_ENT();

	err = mods_find_pci_dev(client, pcidev, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 pcidev->domain,
				 pcidev->bus,
				 pcidev->device,
				 pcidev->function);
		LOG_EXT();
		return err;
	}

	err = check_flr(dev);
	if (unlikely(err)) {
		cl_error(
			 "function level reset not supported on dev %04x:%02x:%02x.%x\n",
			 pcidev->domain,
			 pcidev->bus,
			 pcidev->device,
			 pcidev->function);
		goto error;
	}

#if KERNEL_VERSION(2, 32, 0) <= MODS_KERNEL_VERSION
	pm_runtime_get_sync(&dev->dev);
#endif

	err = pci_reset_function(dev);

#if KERNEL_VERSION(2, 32, 0) <= MODS_KERNEL_VERSION
	pm_runtime_put(&dev->dev);
#endif

	if (unlikely(err))
		cl_error("pcie_flr failed on dev %04x:%02x:%02x.%x\n",
			 pcidev->domain,
			 pcidev->bus,
			 pcidev->device,
			 pcidev->function);
	else
		cl_info("pcie_flr succeeded on dev %04x:%02x:%02x.%x\n",
			pcidev->domain,
			pcidev->bus,
			pcidev->device,
			pcidev->function);

error:
	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

#ifdef MODS_HAS_DEV_PROPS
int esc_mods_read_dev_property(struct mods_client            *client,
			       struct MODS_READ_DEV_PROPERTY *p)
{
	struct pci_dev *dev = NULL;
	int             err = -EINVAL;

	LOG_ENT();

	if (unlikely(p->type != MODS_PROP_TYPE_U64)) {
		cl_error("invalid property type %u\n", p->type);
		goto error;
	}

	if (unlikely(sizeof(u64) * p->array_size > sizeof(p->output))) {
		cl_error("requested size %zu exceeds output array size %zu\n",
			 sizeof(u64) * p->array_size,
			 sizeof(p->output));
		goto error;
	}

	if (unlikely(p->array_size == 0)) {
		cl_error("invalid output array size 0\n");
		goto error;
	}

	if (!memchr(p->prop_name, 0, sizeof(p->prop_name))) {
		cl_error("invalid property name, misses terminating NUL\n");
		goto error;
	}

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 p->pci_device.domain,
				 p->pci_device.bus,
				 p->pci_device.device,
				 p->pci_device.function);
		goto error;
	}

	err = device_property_read_u64_array(&dev->dev, p->prop_name,
					     (u64 *)p->output, p->array_size);
	if (unlikely(err))
		cl_info("failed to read property %s\n", p->prop_name);

error:
	pci_dev_put(dev);
	LOG_EXT();
	return err;
}
#endif

#ifdef MODS_HAS_DMA_MAP_RESOURCE

static bool check_bar_mapping(const struct mods_pci_res_map_info *existing,
			      const struct pci_dev *local_dev,
			      phys_addr_t phys_addr,
			      size_t size)
{
	phys_addr_t existing_end;
	phys_addr_t new_end;

	if (existing->local_dev != local_dev)
		return false;

	existing_end = existing->phys_addr + existing->size;
	new_end      = phys_addr + size;

	/* [phys_addr, new_end) overlaps [existing->phys_addr, existing_end) */
	return phys_addr < existing_end && existing->phys_addr < new_end;
}

int esc_mods_pci_map_resource(struct mods_client    *client,
			      struct MODS_PCI_MAP_RESOURCE *p)
{
	struct pci_dev               *local_dev  = NULL;
	struct pci_dev               *remote_dev = NULL;
	struct mods_pci_res_map_info *p_res_map  = NULL;
	struct mods_pci_res_map_info *cur        = NULL;
	unsigned int                  bar_resource_offset;
	resource_size_t               bar_start;
	resource_size_t               bar_size;
	phys_addr_t                   phys_addr;
	dma_addr_t                    dma_addr   = 0;
	size_t                        size;
	bool                          dma_mapped = false;
	bool                          mtx_locked = false;
	int                           err        = 0;

	LOG_ENT();

	/* Reject non-zero explicit padding so the field can be repurposed later. */
	if (unlikely(p->padding)) {
		cl_error("padding field must be zero\n");
		LOG_EXT();
		return -EINVAL;
	}

	/* Find both devices */
	err = mods_find_pci_dev(client, &p->local_pci_device, &local_dev);
	if (unlikely(err)) {
		cl_error("local dev %04x:%02x:%02x.%x not found\n",
			 p->local_pci_device.domain, p->local_pci_device.bus,
			 p->local_pci_device.device, p->local_pci_device.function);
		LOG_EXT();
		return err;
	}

	err = mods_find_pci_dev(client, &p->remote_pci_device, &remote_dev);
	if (unlikely(err)) {
		cl_error("remote dev %04x:%02x:%02x.%x not found\n",
			 p->remote_pci_device.domain, p->remote_pci_device.bus,
			 p->remote_pci_device.device, p->remote_pci_device.function);
		goto error;
	}

	if (unlikely(local_dev == remote_dev)) {
		cl_error("local and remote PCI device cannot be the same (%04x:%02x:%02x.%x)\n",
			 p->local_pci_device.domain,
			 p->local_pci_device.bus,
			 p->local_pci_device.device,
			 p->local_pci_device.function);
		err = -EINVAL;
		goto error;
	}

	err = pci_bar_index_to_resource(remote_dev, p->bar_index, &bar_resource_offset);
	if (unlikely(err)) {
		cl_error("invalid BAR index %u\n", p->bar_index);
		goto error;
	}

	/* P2P mapping only targets the remote device's standard BARs. */
	if (unlikely(bar_resource_offset > PCI_STD_RESOURCE_END)) {
		cl_error("BAR%u is not a standard BAR\n", p->bar_index);
		err = -EINVAL;
		goto error;
	}

	bar_start = pci_resource_start(remote_dev, bar_resource_offset);
	bar_size  = pci_resource_len(remote_dev, bar_resource_offset);

	if (unlikely(!bar_size)) {
		cl_error("invalid BAR size for BAR%u\n", p->bar_index);
		err = -EINVAL;
		goto error;
	}

	if (unlikely(!(pci_resource_flags(remote_dev, bar_resource_offset) &
		       IORESOURCE_MEM))) {
		cl_error("BAR%u of remote dev is not a memory BAR\n", p->bar_index);
		err = -EINVAL;
		goto error;
	}

	if (unlikely(!p->page_count)) {
		cl_error("page_count must be non-zero\n");
		err = -EINVAL;
		goto error;
	}

	size = (size_t)p->page_count * PAGE_SIZE;
	if (unlikely(size / PAGE_SIZE != p->page_count)) {
		cl_error("page_count overflow\n");
		err = -EINVAL;
		goto error;
	}

	if (unlikely(p->physical_address + size < p->physical_address ||
		     p->physical_address < bar_start ||
		     p->physical_address + size > bar_start + bar_size)) {
		cl_error("range [0x%llx, 0x%llx) outside BAR%u [0x%llx, 0x%llx)\n",
			 (u64)p->physical_address,
			 (u64)(p->physical_address + size),
			 p->bar_index,
			 bar_start,
			 bar_start + bar_size);
		err = -EINVAL;
		goto error;
	}

	phys_addr = (phys_addr_t)p->physical_address;

	/*
	 * Allocate the tracking entry and perform the IOMMU mapping *outside*
	 * the client mutex. Both kzalloc(GFP_KERNEL) and dma_map_resource()
	 * can sleep (memory reclaim, IOMMU page-table updates, etc.), and we
	 * don't want to block other clients holding client->mtx during those
	 * operations.
	 */
	p_res_map = MODS_ZALLOC(*p_res_map);
	if (unlikely(!p_res_map)) {
		err = -ENOMEM;
		goto error;
	}
	atomic_inc(&client->num_allocs);

	dma_addr = dma_map_resource(&local_dev->dev, phys_addr, size,
				    DMA_BIDIRECTIONAL, 0);
	if (unlikely(dma_mapping_error(&local_dev->dev, dma_addr))) {
		cl_error("failed to map peer BAR PA into local device's IOMMU table\n");
		err = -EIO;
		goto error;
	}
	dma_mapped = true;

	p_res_map->local_dev      = local_dev;
	p_res_map->dma_addr       = dma_addr;
	p_res_map->phys_addr      = phys_addr;
	p_res_map->size           = size;
	p_res_map->bar_index      = p->bar_index;

	/* Mutex is held only for the conflict check + list insert. */
	if (unlikely(mutex_lock_interruptible(&client->mtx))) {
		err = -EINTR;
		goto error;
	}
	mtx_locked = true;

	list_for_each_entry(cur, &client->pci_res_map_list, list) {
		if (unlikely(check_bar_mapping(cur, local_dev, phys_addr,
					       size))) {
			cl_error("new mapping [0x%llx, 0x%llx) for local dev %04x:%02x:%02x.%x conflicts with existing [0x%llx, 0x%llx)\n",
				 (u64)phys_addr,
				 (u64)(phys_addr + size),
				 p->local_pci_device.domain,
				 p->local_pci_device.bus,
				 p->local_pci_device.device,
				 p->local_pci_device.function,
				 (u64)cur->phys_addr,
				 (u64)(cur->phys_addr + cur->size));
			err = -EEXIST;
			goto error;
		}
	}

	list_add(&p_res_map->list, &client->pci_res_map_list);
	mutex_unlock(&client->mtx);
	mtx_locked = false;

	p->iova = (u64)(dma_addr); /* return IOVA to userspace */

	cl_debug(DEBUG_PCI,
		 "mapped BAR%u of %04x:%02x:%02x.%x (PA=0x%llx) into %04x:%02x:%02x.%x as IOVA=0x%llx, size=0x%zx\n",
		 p->bar_index,
		 p->remote_pci_device.domain, p->remote_pci_device.bus,
		 p->remote_pci_device.device, p->remote_pci_device.function,
		 (u64)phys_addr,
		 p->local_pci_device.domain, p->local_pci_device.bus,
		 p->local_pci_device.device, p->local_pci_device.function,
		 (u64)dma_addr, size);

	pci_dev_put(remote_dev);
	remote_dev = NULL;
	local_dev  = NULL;
	p_res_map  = NULL;
	dma_mapped = false; /* ownership transferred to p_res_map on the list */

	LOG_EXT();
	return 0;

error:
	if (mtx_locked)
		mutex_unlock(&client->mtx);
	if (dma_mapped)
		dma_unmap_resource(&local_dev->dev, dma_addr, size,
				   DMA_BIDIRECTIONAL, 0);
	if (p_res_map)
		atomic_dec(&client->num_allocs);
	kfree(p_res_map);
	if (remote_dev)
		pci_dev_put(remote_dev);
	if (local_dev)
		pci_dev_put(local_dev);

	LOG_EXT();
	return err;
}

int esc_mods_pci_unmap_resource(struct mods_client    *client,
				struct MODS_PCI_UNMAP_RESOURCE *p)
{
	struct pci_dev               *dev;
	struct mods_pci_res_map_info *cur;
	struct mods_pci_res_map_info *found = NULL;
	int                           err;

	LOG_ENT();

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		cl_error("dev %04x:%02x:%02x.%x not found\n",
			 p->pci_device.domain, p->pci_device.bus,
			 p->pci_device.device, p->pci_device.function);
		LOG_EXT();
		return err;
	}

	if (unlikely(mutex_lock_interruptible(&client->mtx))) {
		pci_dev_put(dev);
		LOG_EXT();
		return -EINTR;
	}

	list_for_each_entry(cur, &client->pci_res_map_list, list) {
		if (cur->local_dev == dev && cur->dma_addr == p->iova) {
			found = cur;
			list_del(&cur->list);
			break;
		}
	}
	mutex_unlock(&client->mtx);

	if (unlikely(!found)) {
		cl_error("no mapping at IOVA=0x%llx for dev %04x:%02x:%02x.%x\n",
			 p->iova,
			 p->pci_device.domain,
			 p->pci_device.bus,
			 p->pci_device.device,
			 p->pci_device.function);
		pci_dev_put(dev);
		LOG_EXT();
		return -EINVAL;
	}

	dma_unmap_resource(&dev->dev, found->dma_addr, found->size, DMA_BIDIRECTIONAL, 0);
	pci_dev_put(found->local_dev);
	kfree(found);
	atomic_dec(&client->num_allocs);
	pci_dev_put(dev);

	LOG_EXT();
	return 0;
}

void mods_free_pci_res_maps(struct mods_client *client)
{
	struct mods_pci_res_map_info *cur;

	for (;;) {
		mutex_lock(&client->mtx);
		cur = list_first_entry_or_null(&client->pci_res_map_list,
					       struct mods_pci_res_map_info,
					       list);
		if (cur)
			list_del(&cur->list);
		mutex_unlock(&client->mtx);

		if (!cur)
			break;

		dma_unmap_resource(&cur->local_dev->dev, cur->dma_addr,
				   cur->size, DMA_BIDIRECTIONAL, 0);
		pci_dev_put(cur->local_dev);
		kfree(cur);
		atomic_dec(&client->num_allocs);
	}
}
#endif
