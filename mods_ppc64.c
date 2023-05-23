// SPDX-License-Identifier: GPL-2.0
/*
 * This file is part of NVIDIA MODS kernel driver.
 *
 * Copyright (c) 2017-2022, NVIDIA CORPORATION.  All rights reserved.
 *
 * NVIDIA MODS kernel driver is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * NVIDIA MODS kernel driver is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NVIDIA MODS kernel driver.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "mods_internal.h"

#include <linux/fs.h>

#ifdef MODS_HAS_PNV_PCI_GET_NPU_DEV
static struct pci_dev *get_npu_dev(struct pci_dev *dev, int index)
{
	return pnv_pci_get_npu_dev(dev, index);
}
#else
#define get_npu_dev(dev, index) (NULL)
#endif

int has_npu_dev(struct pci_dev *dev, int index)
{
	struct pci_dev *npu_dev = get_npu_dev(dev, index);

	/* We should call pci_dev_put(npu_dev), but it's currently crashing */

	return npu_dev != NULL;
}

static struct NVL_TRAINED *mods_find_nvlink_sysmem_trained(
				struct mods_client *client,
				struct pci_dev     *dev)
{
	struct list_head   *plist_head;
	struct list_head   *plist_iter;
	struct NVL_TRAINED *p_nvl_trained;

	plist_head = &client->nvlink_sysmem_trained_list;

	list_for_each(plist_iter, plist_head) {
		p_nvl_trained = list_entry(plist_iter,
					   struct NVL_TRAINED,
					   list);
		if (dev == p_nvl_trained->dev)
			return p_nvl_trained;
	}

	/* The device has never had its dma mask changed */
	return NULL;
}

static int mods_register_nvlink_sysmem_trained(struct mods_client *client,
					       struct pci_dev     *dev,
					       u8                  trained)
{
	struct NVL_TRAINED *p_nvl_trained;

	p_nvl_trained = mods_find_nvlink_sysmem_trained(client, dev);
	if (p_nvl_trained != NULL) {
		p_nvl_trained->trained = trained;
		return OK;
	}

	if (unlikely(mutex_lock_interruptible(&client->mtx)))
		return -EINTR;

	p_nvl_trained = kzalloc(sizeof(struct NVL_TRAINED),
				GFP_KERNEL | __GFP_NORETRY);
	if (unlikely(!p_nvl_trained)) {
		cl_error("failed to allocate NvLink trained struct\n");
		LOG_EXT();
		return -ENOMEM;
	}
	atomic_inc(&client->num_allocs);

	p_nvl_trained->dev     = pci_dev_get(dev);
	p_nvl_trained->trained = trained;

	list_add(&p_nvl_trained->list,
		 &client->nvlink_sysmem_trained_list);

	cl_debug(DEBUG_MEM,
		 "registered NvLink trained on dev %04x:%02x:%02x.%x\n",
		 pci_domain_nr(dev->bus),
		 dev->bus->number,
		 PCI_SLOT(dev->devfn),
		 PCI_FUNC(dev->devfn));
	mutex_unlock(&client->mtx);
	return OK;
}

static int mods_unregister_nvlink_sysmem_trained(struct mods_client *client,
						 struct pci_dev     *dev)
{
	struct NVL_TRAINED *p_nvl_trained;
	struct list_head   *head   = &client->nvlink_sysmem_trained_list;
	struct list_head   *iter;

	LOG_ENT();

	if (unlikely(mutex_lock_interruptible(&client->mtx)))
		return -EINTR;

	list_for_each(iter, head) {
		p_nvl_trained =
			list_entry(iter, struct NVL_TRAINED, list);

		if (p_nvl_trained->dev == dev) {
			list_del(iter);

			mutex_unlock(&client->mtx);

			cl_debug(DEBUG_MEM,
				 "unregistered NvLink trained on dev %04x:%02x:%02x.%x\n",
				 pci_domain_nr(p_nvl_trained->dev->bus),
				 p_nvl_trained->dev->bus->number,
				 PCI_SLOT(p_nvl_trained->dev->devfn),
				 PCI_FUNC(p_nvl_trained->dev->devfn));

			pci_dev_put(dev);

			kfree(p_nvl_trained);
			atomic_dec(&client->num_allocs);

			LOG_EXT();
			return OK;
		}
	}

	mutex_unlock(&client->mtx);

	cl_error(
		"failed to unregister NvLink trained on dev %04x:%02x:%02x.%x\n",
		pci_domain_nr(dev->bus),
		dev->bus->number,
		PCI_SLOT(dev->devfn),
		PCI_FUNC(dev->devfn));
	LOG_EXT();

	return -EINVAL;

}

int mods_unregister_all_nvlink_sysmem_trained(struct mods_client *client)
{
	struct list_head *head = &client->nvlink_sysmem_trained_list;
	struct list_head *iter;
	struct list_head *tmp;

	list_for_each_safe(iter, tmp, head) {
		struct NVL_TRAINED *p_nvl_trained;
		int err;

		p_nvl_trained =
			list_entry(iter, struct NVL_TRAINED, list);
		err = mods_unregister_nvlink_sysmem_trained(client,
							p_nvl_trained->dev);
		if (err)
			return err;
	}

	return OK;
}

int mods_is_nvlink_sysmem_trained(struct mods_client *client,
				  struct pci_dev     *dev)
{
	struct NVL_TRAINED    *p_nvl_trained;

	p_nvl_trained = mods_find_nvlink_sysmem_trained(client, dev);
	if (p_nvl_trained != NULL)
		return p_nvl_trained->trained;

	return false;
}

int esc_mods_set_nvlink_sysmem_trained(struct mods_client *client,
				struct MODS_SET_NVLINK_SYSMEM_TRAINED *p)
{
	struct pci_dev *dev;
	int             err;

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

	err = mods_register_nvlink_sysmem_trained(client, dev, p->trained);

	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

static struct PPC_TCE_BYPASS *mods_find_ppc_tce_bypass(
				struct mods_client *client,
				struct pci_dev     *dev)
{
	struct list_head      *plist_head;
	struct list_head      *plist_iter;
	struct PPC_TCE_BYPASS *p_ppc_tce_bypass;

	plist_head = &client->ppc_tce_bypass_list;

	list_for_each(plist_iter, plist_head) {
		p_ppc_tce_bypass = list_entry(plist_iter,
					  struct PPC_TCE_BYPASS,
					  list);
		if (dev == p_ppc_tce_bypass->dev)
			return p_ppc_tce_bypass;
	}

	/* The device has never had its dma mask changed */
	return NULL;
}

static int mods_register_ppc_tce_bypass(struct mods_client *client,
					struct pci_dev     *dev,
					u64                 original_mask)
{
	struct PPC_TCE_BYPASS *p_ppc_tce_bypass;

	/* only register the first time in order to restore the true actual dma
	 * mask
	 */
	if (mods_find_ppc_tce_bypass(client, dev) != NULL) {
		cl_debug(DEBUG_MEM,
			 "TCE bypass already registered on dev %04x:%02x:%02x.%x\n",
			 pci_domain_nr(dev->bus),
			 dev->bus->number,
			 PCI_SLOT(dev->devfn),
			 PCI_FUNC(dev->devfn));
		return OK;
	}

	if (unlikely(mutex_lock_interruptible(&client->mtx)))
		return -EINTR;

	p_ppc_tce_bypass = kzalloc(sizeof(struct PPC_TCE_BYPASS),
				   GFP_KERNEL | __GFP_NORETRY);
	if (unlikely(!p_ppc_tce_bypass)) {
		cl_error("failed to allocate TCE bypass struct\n");
		LOG_EXT();
		return -ENOMEM;
	}
	atomic_inc(&client->num_allocs);

	p_ppc_tce_bypass->dev      = pci_dev_get(dev);
	p_ppc_tce_bypass->dma_mask = original_mask;

	list_add(&p_ppc_tce_bypass->list,
		 &client->ppc_tce_bypass_list);

	cl_debug(DEBUG_MEM,
		 "registered TCE bypass on dev %04x:%02x:%02x.%x\n",
		 pci_domain_nr(dev->bus),
		 dev->bus->number,
		 PCI_SLOT(dev->devfn),
		 PCI_FUNC(dev->devfn));
	mutex_unlock(&client->mtx);
	return OK;
}

static int mods_unregister_ppc_tce_bypass(struct mods_client *client,
					  struct pci_dev     *dev)
{
	struct PPC_TCE_BYPASS *p_ppc_tce_bypass;
	struct list_head      *head = &client->ppc_tce_bypass_list;
	struct list_head      *iter;

	LOG_ENT();

	if (unlikely(mutex_lock_interruptible(&client->mtx)))
		return -EINTR;

	list_for_each(iter, head) {
		p_ppc_tce_bypass =
			list_entry(iter, struct PPC_TCE_BYPASS, list);

		if (p_ppc_tce_bypass->dev == dev) {
			int err = -EINVAL;

			list_del(iter);

			mutex_unlock(&client->mtx);

			err = pci_set_dma_mask(p_ppc_tce_bypass->dev,
					       p_ppc_tce_bypass->dma_mask);
			dma_set_coherent_mask(&p_ppc_tce_bypass->dev->dev,
					      dev->dma_mask);
			cl_debug(DEBUG_MEM,
				 "restored dma_mask on dev %04x:%02x:%02x.%x to %llx\n",
				 pci_domain_nr(p_ppc_tce_bypass->dev->bus),
				 p_ppc_tce_bypass->dev->bus->number,
				 PCI_SLOT(p_ppc_tce_bypass->dev->devfn),
				 PCI_FUNC(p_ppc_tce_bypass->dev->devfn),
				 p_ppc_tce_bypass->dma_mask);

			pci_dev_put(dev);

			kfree(p_ppc_tce_bypass);
			atomic_dec(&client->num_allocs);

			LOG_EXT();
			return err;
		}
	}

	mutex_unlock(&client->mtx);

	cl_error("failed to unregister TCE bypass on dev %04x:%02x:%02x.%x\n",
		 pci_domain_nr(dev->bus),
		 dev->bus->number,
		 PCI_SLOT(dev->devfn),
		 PCI_FUNC(dev->devfn));
	LOG_EXT();

	return -EINVAL;

}

int mods_unregister_all_ppc_tce_bypass(struct mods_client *client)
{
	int              err   = OK;
	struct list_head *head = &client->ppc_tce_bypass_list;
	struct list_head *iter;
	struct list_head *tmp;

	list_for_each_safe(iter, tmp, head) {
		struct PPC_TCE_BYPASS *p_ppc_tce_bypass;

		p_ppc_tce_bypass =
			list_entry(iter, struct PPC_TCE_BYPASS, list);
		err = mods_unregister_ppc_tce_bypass(client,
						     p_ppc_tce_bypass->dev);
		if (err)
			break;
	}

	return err;
}

int esc_mods_set_ppc_tce_bypass(struct mods_client             *client,
				struct MODS_SET_PPC_TCE_BYPASS *p)
{
	int             err = OK;
	dma_addr_t      dma_addr;
	struct pci_dev *dev;
	u64             original_dma_mask;
	u32             bypass_mode     = p->mode;
	u32             cur_bypass_mode = MODS_PPC_TCE_BYPASS_OFF;
	u64             dma_mask        = DMA_BIT_MASK(64);

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
		return -EINVAL;
	}

	original_dma_mask = dev->dma_mask;

	if (bypass_mode == MODS_PPC_TCE_BYPASS_DEFAULT)
		bypass_mode = mods_get_ppc_tce_bypass();

	if (original_dma_mask == DMA_BIT_MASK(64))
		cur_bypass_mode = MODS_PPC_TCE_BYPASS_ON;

	/*
	 * Linux on IBM POWER8 offers 2 different DMA set-ups, sometimes
	 * referred to as "windows".
	 *
	 * The "default window" provides a 2GB region of PCI address space
	 * located below the 32-bit line. The IOMMU is used to provide a
	 * "rich" mapping--any page in system memory can be mapped at an
	 * arbitrary address within this window. The mappings are dynamic
	 * and pass in and out of being as pci_map*()/pci_unmap*() calls
	 * are made.
	 *
	 * Dynamic DMA Windows (sometimes "Huge DDW", also PPC TCE Bypass "ON")
	 * provides a linear
	 * mapping of the system's entire physical address space at some
	 * fixed offset above the 59-bit line. IOMMU is still used, and
	 * pci_map*()/pci_unmap*() are still required, but mappings are
	 * static. They're effectively set up in advance, and any given
	 * system page will always map to the same PCI bus address. I.e.
	 *   physical 0x00000000xxxxxxxx => PCI 0x08000000xxxxxxxx
	 *
	 * Linux on POWER8 will only provide the DDW-style full linear
	 * mapping when the driver claims support for 64-bit DMA addressing
	 * (a pre-requisite because the PCI addresses used in this case will
	 * be near the top of the 64-bit range). The linear mapping
	 * is not available in all system configurations.
	 *
	 * Detect whether the linear mapping is present by claiming
	 * 64-bit support and then mapping physical page 0. For historical
	 * reasons, Linux on POWER8 will never map a page to PCI address 0x0.
	 * In the "default window" case page 0 will be mapped to some
	 * non-zero address below the 32-bit line.  In the
	 * DDW/linear-mapping case, it will be mapped to address 0 plus
	 * some high-order offset.
	 *
	 * If the linear mapping is present and sane then return the offset
	 * as the starting address for all DMA mappings.
	 */
	if ((bypass_mode != MODS_PPC_TCE_BYPASS_DEFAULT) &&
	    (cur_bypass_mode != bypass_mode)) {
		/* Set DMA mask appropriately here */
		if (bypass_mode == MODS_PPC_TCE_BYPASS_OFF)
			dma_mask = p->device_dma_mask;

		err = pci_set_dma_mask(dev, dma_mask);
		if (unlikely(err)) {
			cl_error(
				"pci_set_dma_mask failed on dev %04x:%02x:%02x.%x\n",
				p->pci_device.domain,
				p->pci_device.bus,
				p->pci_device.device,
				p->pci_device.function);
			pci_dev_put(dev);
			LOG_EXT();
			return err;
		}
	}

	dma_addr = pci_map_single(dev, NULL, 1, DMA_BIDIRECTIONAL);
	err = pci_dma_mapping_error(dev, dma_addr);
	if (unlikely(err)) {
		pci_set_dma_mask(dev, original_dma_mask);
		cl_error("pci_map_single failed on dev %04x:%02x:%02x.%x\n",
			 p->pci_device.domain,
			 p->pci_device.bus,
			 p->pci_device.device,
			 p->pci_device.function);
		pci_dev_put(dev);
		LOG_EXT();
		return err;
	}
	pci_unmap_single(dev, dma_addr, 1, DMA_BIDIRECTIONAL);

	if (bypass_mode == MODS_PPC_TCE_BYPASS_ON) {
		int failed = false;

		/*
		 * From IBM: "For IODA2, native DMA bypass or KVM TCE-based
		 * implementation of full 64-bit DMA support will establish a
		 * window in address-space with the high 14 bits being constant
		 * and the bottom up-to-50 bits varying with the mapping."
		 *
		 * Unfortunately, we don't have any good interfaces or
		 * definitions from the kernel to get information about the DMA
		 * offset assigned by OS. However, we have been told that the
		 * offset will be defined by the top 14 bits of the address,
		 * and bits 40-49 will not vary for any DMA mappings until 1TB
		 * of system memory is surpassed; this limitation is essential
		 * for us to function properly since our current GPUs only
		 * support 40 physical address bits. We are in a fragile place
		 * where we need to tell the OS that we're capable of 64-bit
		 * addressing, while relying on the assumption that the top 24
		 * bits will not vary in this case.
		 *
		 * The way we try to compute the window, then, is mask the trial
		 * mapping against the DMA capabilities of the device. That way,
		 * devices with greater addressing capabilities will only take
		 * the bits it needs to define the window.
		 */
		if ((dma_addr & DMA_BIT_MASK(32)) != 0) {
			/*
			 * Huge DDW not available - page 0 mapped to non-zero
			 * address below the 32-bit line.
			 */
			cl_warn("enabling PPC TCE bypass mode failed due to platform on dev %04x:%02x:%02x.%x\n",
				p->pci_device.domain,
				p->pci_device.bus,
				p->pci_device.device,
				p->pci_device.function);
			failed = true;
		} else if ((dma_addr & original_dma_mask) != 0) {
			/*
			 * The physical window straddles our addressing limit
			 * boundary, e.g., for an adapter that can address up to
			 * 1TB, the window crosses the 40-bit limit so that the
			 * lower end of the range has different bits 63:40 than
			 * the higher end of the range. We can only handle a
			 * single, static value for bits 63:40, so we must fall
			 * back here.
			 */
			u64 memory_size = get_num_physpages() * PAGE_SIZE;

			if ((dma_addr & ~original_dma_mask) !=
			    ((dma_addr + memory_size) & ~original_dma_mask)) {

				cl_warn("enabling PPC TCE bypass mode failed due to memory size on dev %04x:%02x:%02x.%x\n",
					p->pci_device.domain,
					p->pci_device.bus,
					p->pci_device.device,
					p->pci_device.function);
				failed = true;
			}
		}
		if (failed)
			pci_set_dma_mask(dev, original_dma_mask);
	}

	cl_debug(DEBUG_MEM,
		 "%s ppc tce bypass on dev %04x:%02x:%02x.%x with dma mask 0x%llx\n",
		 (dev->dma_mask == DMA_BIT_MASK(64)) ? "enabled" : "disabled",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function,
		 dev->dma_mask);

	p->dma_base_address = dma_addr & ~(p->device_dma_mask);

	cl_debug(DEBUG_MEM,
		 "dma base address 0x%0llx on dev %04x:%02x:%02x.%x\n",
		 p->dma_base_address,
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function);

	/* Update the coherent mask to match */
	dma_set_coherent_mask(&dev->dev, dev->dma_mask);

	if (original_dma_mask != dev->dma_mask)
		err = mods_register_ppc_tce_bypass(client,
						   dev,
						   original_dma_mask);

	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

int esc_mods_get_ats_address_range(struct mods_client                *client,
				   struct MODS_GET_ATS_ADDRESS_RANGE *p)
{
	struct pci_dev	   *dev      = NULL;
	struct pci_dev	   *npu_dev  = NULL;
	struct device_node *mem_node = NULL;
	const __u32	   *val32    = NULL;
	const __u64	   *val64;
	int		    len;
	int		    err      = -EINVAL;

	LOG_ENT();

	cl_debug(DEBUG_PCI,
		 "get ats addr, dev %04x:%02x:%02x:%x, npu index %d\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function,
		 p->npu_index);

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 p->pci_device.domain,
				 p->pci_device.bus,
				 p->pci_device.device,
				 p->pci_device.function);
		goto exit;
	}

	err = -ENODEV;

	npu_dev = get_npu_dev(dev, p->npu_index);
	if (unlikely(npu_dev == NULL)) {
		cl_error("NPU device for dev %04x:%02x:%02x.%x not found\n",
			 p->pci_device.domain,
			 p->pci_device.bus,
			 p->pci_device.device,
			 p->pci_device.function);
		goto exit;
	}

	p->npu_device.domain   = pci_domain_nr(npu_dev->bus);
	p->npu_device.bus      = npu_dev->bus->number;
	p->npu_device.device   = PCI_SLOT(npu_dev->devfn);
	p->npu_device.function = PCI_FUNC(npu_dev->devfn);

	cl_debug(DEBUG_PCI,
		 "found NPU device %04x:%02x:%02x.%x\n",
		 p->npu_device.domain,
		 p->npu_device.bus,
		 p->npu_device.device,
		 p->npu_device.function);

	if (npu_dev->dev.of_node)
		val32 = (const __u32 *)of_get_property(npu_dev->dev.of_node,
						       "memory-region",
						       &len);
	if (!val32 || len < 4) {
		cl_error("property memory-region for NPU not found\n");
		goto exit;
	}

	mem_node = of_find_node_by_phandle(be32_to_cpu(*val32));
	if (!mem_node) {
		cl_error("node memory-region for NPU not found\n");
		goto exit;
	}

	p->numa_memory_node = of_node_to_nid(mem_node);
	if (p->numa_memory_node == NUMA_NO_NODE) {
		cl_error("NUMA node for NPU not found\n");
		goto exit;
	}

	val64 = (const __u64 *)of_get_property(npu_dev->dev.of_node,
					       "ibm,device-tgt-addr",
					       &len);
	if (!val64 || len < 8) {
		cl_error("property ibm,device-tgt-addr for NPU not found\n");
		goto exit;
	}

	p->phys_addr = be64_to_cpu(*val64);

	val64 = (const __u64 *)of_get_property(mem_node, "reg", &len);
	if (!val64 || len < 16) {
		cl_error("property reg for memory region not found\n");
		goto exit;
	}

	p->guest_addr    = be64_to_cpu(val64[0]);
	p->aperture_size = be64_to_cpu(val64[1]);

	err = OK;

exit:
	of_node_put(mem_node);
	/* We should call pci_dev_put(npu_dev), but it's currently crashing */
	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

int esc_mods_get_nvlink_line_rate(struct mods_client               *client,
				  struct MODS_GET_NVLINK_LINE_RATE *p)
{
	struct pci_dev *dev     = NULL;
	struct pci_dev *npu_dev = NULL;
	const __u32    *val32   = NULL;
	int             len;
	int             err     = -EINVAL;

	LOG_ENT();

	cl_debug(DEBUG_PCI,
		 "get nvlink speed, dev %04x:%02x:%02x.%x, npu index %d\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function,
		 p->npu_index);

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 p->pci_device.domain,
				 p->pci_device.bus,
				 p->pci_device.device,
				 p->pci_device.function);
		goto exit;
	}

	err = -ENODEV;

	npu_dev = get_npu_dev(dev, p->npu_index);
	if (unlikely(npu_dev == NULL)) {
		cl_error("NPU device for dev %04x:%02x:%02x.%x not found\n",
			 p->pci_device.domain,
			 p->pci_device.bus,
			 p->pci_device.device,
			 p->pci_device.function);
		goto exit;
	}

	cl_debug(DEBUG_PCI,
		 "found NPU device %04x:%02x:%02x.%x\n",
		 pci_domain_nr(npu_dev->bus),
		 npu_dev->bus->number,
		 PCI_SLOT(npu_dev->devfn),
		 PCI_FUNC(npu_dev->devfn));

	if (npu_dev->dev.of_node)
		val32 = (const __u32 *)of_get_property(npu_dev->dev.of_node,
						       "ibm,nvlink-speed",
						       &len);
	if (!val32) {
		cl_error("property ibm,nvlink-speed for NPU not found\n");
		goto exit;
	}

	p->speed = be32_to_cpup(val32);
	if (!p->speed) {
		cl_error("ibm,nvlink-speed value for NPU not valid\n");
		goto exit;
	}

	err = OK;

exit:
	/* We should call pci_dev_put(npu_dev), but it's currently crashing */
	pci_dev_put(dev);
	LOG_EXT();
	return err;
}

int esc_mods_pci_hot_reset(struct mods_client        *client,
			   struct MODS_PCI_HOT_RESET *p)
{
	struct pci_dev *dev;
	int err;

	LOG_ENT();

	cl_debug(DEBUG_PCI,
		 "pci_hot_reset dev %04x:%02x:%02x.%x\n",
		 p->pci_device.domain,
		 p->pci_device.bus,
		 p->pci_device.device,
		 p->pci_device.function);

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error(
				"pci_hot_reset cannot find dev %04x:%02x:%02x.%x\n",
				p->pci_device.domain,
				p->pci_device.bus,
				p->pci_device.device,
				p->pci_device.function);
		LOG_EXT();
		return err;
	}

	err = pci_set_pcie_reset_state(dev, pcie_hot_reset);
	if (unlikely(err))
		cl_error("pci_hot_reset failed on dev %04x:%02x:%02x.%x\n",
			 p->pci_device.domain,
			 p->pci_device.bus,
			 p->pci_device.device,
			 p->pci_device.function);
	else {

		err = pci_set_pcie_reset_state(dev, pcie_deassert_reset);
		if (unlikely(err))
			cl_error(
				"pci_hot_reset deassert failed on dev %04x:%02x:%02x.%x\n",
				p->pci_device.domain,
				p->pci_device.bus,
				p->pci_device.device,
				p->pci_device.function);
	}

	pci_dev_put(dev);
	LOG_EXT();
	return err;
}
