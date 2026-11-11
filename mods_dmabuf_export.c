// SPDX-License-Identifier: GPL-2.0-only
/* SPDX-FileCopyrightText: Copyright (c) 2008-2026, NVIDIA CORPORATION.  All rights reserved. */

#include "mods_internal.h"

#if defined(MODS_HAS_DMABUF_EXPORT)

#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/pci_ids.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define MODS_DMABUF_MAX_MAPPED_RANGES 4096U
#define MODS_DMABUF_FB_BAR_INDEX 1U

/* Protects the lists below. */
static LIST_HEAD(mods_dmabuf_exports);
static LIST_HEAD(mods_dmabuf_pci_removals);
static LIST_HEAD(mods_dmabuf_pci_resets);
static DEFINE_MUTEX(mods_dmabuf_mtx);

struct mods_dmabuf_export {
	struct list_head                 list;
	struct MODS_DMABUF_EXPORT_RANGE *ranges;
	struct mods_client              *client;
	struct pci_dev                  *dev;
	struct file                     *mods_filp;
	struct pid                      *owner_tgid;
	u64                              size;
	u32                              range_count;
	u32                              attachment_count;
	bool                             release_guarded;
};

struct mods_dmabuf_pci_remove {
	struct list_head list;
	struct pci_dev  *dev;
};

struct mods_dmabuf_pci_reset {
	struct list_head    list;
	struct pci_dev     *dev;
	struct pci_bus     *bus;
	struct pci_dev     *held_dev;
	struct mods_client *client;
};

static bool mods_dmabuf_dev_is_affected(struct pci_dev *dev, struct pci_dev *root)
{
	struct pci_bus *bus;

	if (dev == root)
		return true;

	for (bus = dev->bus; bus && bus->self; bus = bus->self->bus) {
		if (bus->self == root)
			return true;
	}
	return false;
}

static void dmabuf_lock(void)
{
	mutex_lock(&mods_dmabuf_mtx);
}

static void dmabuf_unlock(void)
{
	mutex_unlock(&mods_dmabuf_mtx);
}

int mods_dmabuf_begin_pci_remove(struct pci_dev *dev, struct mods_dmabuf_pci_remove **pci_remove)
{
	struct mods_dmabuf_pci_remove *remove;
	struct mods_dmabuf_export     *export;
	int                            err = 0;

	remove = MODS_ZALLOC(*remove);
	if (!remove)
		return -ENOMEM;
	remove->dev = dev;

	dmabuf_lock();
	list_for_each_entry(export, &mods_dmabuf_exports, list) {
		if (mods_dmabuf_dev_is_affected(export->dev, dev)) {
			err = -EBUSY;
			break;
		}
	}
	if (!err) {
		list_add(&remove->list, &mods_dmabuf_pci_removals);
		*pci_remove = remove;
	}
	dmabuf_unlock();

	if (err)
		kfree(remove);
	return err;
}

void mods_dmabuf_end_pci_remove(struct mods_dmabuf_pci_remove *pci_remove)
{
	dmabuf_lock();
	list_del(&pci_remove->list);
	dmabuf_unlock();
	kfree(pci_remove);
}

static bool mods_dmabuf_dev_is_on_bus(struct pci_dev *dev, struct pci_bus *root)
{
	struct pci_bus *bus;

	for (bus = dev->bus; bus; bus = bus->self ? bus->self->bus : NULL) {
		if (bus == root)
			return true;
	}
	return false;
}

static int mods_dmabuf_begin_pci_reset(struct pci_dev *dev, struct pci_bus *bus,
				       struct pci_dev *held_dev, struct mods_client *client,
				       struct mods_dmabuf_pci_reset **pci_reset)
{
	struct mods_dmabuf_pci_reset *reset;
	struct mods_dmabuf_pci_reset *pending;
	struct mods_dmabuf_export    *export;
	int                           err = 0;

	reset = MODS_ZALLOC(*reset);
	if (!reset)
		return -ENOMEM;
	reset->dev = dev;
	reset->bus = bus;
	reset->held_dev = held_dev;
	reset->client = client;

	dmabuf_lock();
	if (client) {
		list_for_each_entry(pending, &mods_dmabuf_pci_resets, list) {
			if (pending->client == client && pending->held_dev == held_dev) {
				err = -EALREADY;
				break;
			}
		}
	}
	if (!err) {
		list_for_each_entry(export, &mods_dmabuf_exports, list) {
			if ((dev && export->dev == dev) ||
			    (bus && mods_dmabuf_dev_is_on_bus(export->dev, bus))) {
				err = -EBUSY;
				break;
			}
		}
	}
	if (!err) {
		list_add(&reset->list, &mods_dmabuf_pci_resets);
		*pci_reset = reset;
	}
	dmabuf_unlock();

	if (err)
		kfree(reset);
	return err;
}

int mods_dmabuf_begin_pci_function_reset(struct pci_dev                *dev,
					 struct mods_dmabuf_pci_reset **pci_reset)
{
	return mods_dmabuf_begin_pci_reset(dev, NULL, NULL, NULL, pci_reset);
}

int mods_dmabuf_begin_pci_bus_reset(struct pci_bus *bus, struct mods_dmabuf_pci_reset **pci_reset)
{
	return mods_dmabuf_begin_pci_reset(NULL, bus, NULL, NULL, pci_reset);
}

static void mods_dmabuf_free_pci_reset(struct mods_dmabuf_pci_reset *pci_reset)
{
	if (pci_reset->held_dev)
		pci_dev_put(pci_reset->held_dev);
	kfree(pci_reset);
}

void mods_dmabuf_end_pci_reset(struct mods_dmabuf_pci_reset *pci_reset)
{
	dmabuf_lock();
	list_del(&pci_reset->list);
	dmabuf_unlock();
	mods_dmabuf_free_pci_reset(pci_reset);
}

int esc_mods_dmabuf_acquire_pci_reset_guard(struct mods_client                  *client,
					    struct MODS_DMABUF_PCI_RESET_GUARD *p)
{
	struct mods_dmabuf_pci_reset *reset;
	struct pci_dev                *dev;
	int                            err;

	if (p->reserved || (p->scope != MODS_DMABUF_PCI_RESET_SCOPE_FUNCTION &&
	     p->scope != MODS_DMABUF_PCI_RESET_SCOPE_BUS))
		return -EINVAL;

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (err)
		return err;

	if (p->scope == MODS_DMABUF_PCI_RESET_SCOPE_FUNCTION)
		err = mods_dmabuf_begin_pci_reset(dev, NULL, dev, client, &reset);
	else
		err = mods_dmabuf_begin_pci_reset(NULL, dev->bus, dev, client, &reset);

	if (err) {
		pci_dev_put(dev);
		return err;
	}

	return 0;
}

int esc_mods_dmabuf_release_pci_reset_guard(struct mods_client                  *client,
					    struct MODS_DMABUF_PCI_RESET_GUARD *p)
{
	struct mods_dmabuf_pci_reset *reset;
	struct mods_dmabuf_pci_reset *found = NULL;
	struct pci_dev                *dev;
	int                            err;

	if (p->reserved || (p->scope != MODS_DMABUF_PCI_RESET_SCOPE_FUNCTION &&
	     p->scope != MODS_DMABUF_PCI_RESET_SCOPE_BUS))
		return -EINVAL;

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (err)
		return err;

	dmabuf_lock();
	list_for_each_entry(reset, &mods_dmabuf_pci_resets, list) {
		if (reset->client == client && reset->held_dev == dev &&
		    (!!reset->bus == (p->scope == MODS_DMABUF_PCI_RESET_SCOPE_BUS))) {
			list_del(&reset->list);
			found = reset;
			break;
		}
	}
	dmabuf_unlock();
	pci_dev_put(dev);

	if (!found)
		return -ENOENT;

	mods_dmabuf_free_pci_reset(found);
	return 0;
}

void mods_dmabuf_cleanup_client_reset_guards(struct mods_client *client)
{
	struct mods_dmabuf_pci_reset *reset;
	struct mods_dmabuf_pci_reset *next;
	LIST_HEAD(reset_guards);

	dmabuf_lock();
	list_for_each_entry_safe(reset, next, &mods_dmabuf_pci_resets, list) {
		if (reset->client == client)
			list_move(&reset->list, &reset_guards);
	}
	dmabuf_unlock();

	list_for_each_entry_safe(reset, next, &reset_guards, list) {
		list_del(&reset->list);
		mods_dmabuf_free_pci_reset(reset);
	}
}

static bool mods_dmabuf_pci_remove_pending(struct pci_dev *dev)
{
	struct mods_dmabuf_pci_remove *remove;

	WARN_ON(!mutex_is_locked(&mods_dmabuf_mtx));
	list_for_each_entry(remove, &mods_dmabuf_pci_removals, list) {
		if (mods_dmabuf_dev_is_affected(dev, remove->dev))
			return true;
	}
	return false;
}

static bool mods_dmabuf_pci_reset_pending(struct pci_dev *dev)
{
	struct mods_dmabuf_pci_reset *reset;

	WARN_ON(!mutex_is_locked(&mods_dmabuf_mtx));
	list_for_each_entry(reset, &mods_dmabuf_pci_resets, list) {
		if ((reset->dev && reset->dev == dev) ||
		    (reset->bus && mods_dmabuf_dev_is_on_bus(dev, reset->bus)))
			return true;
	}
	return false;
}

static bool mods_dmabuf_is_nvidia_gpu(struct pci_dev *dev)
{
	u32 class_code = dev->class >> 8;

	return dev->vendor == PCI_VENDOR_ID_NVIDIA && (class_code == PCI_CLASS_DISPLAY_VGA ||
		class_code == PCI_CLASS_DISPLAY_3D);
}

static int mods_dmabuf_validate_owner(struct mods_client *client, struct pci_dev *dev)
{
	struct en_dev_entry *dpriv;
	int                  err = 0;

	mutex_lock(mods_get_irq_mutex());
	dpriv = mods_get_enabled_device_entry(dev);
	if (!dpriv || !is_valid_client_id(dpriv->client_id))
		err = -ENODEV;
	else if (dpriv->client_id != client->client_id)
		err = -EBUSY;
	mutex_unlock(mods_get_irq_mutex());
	return err;
}

static int mods_dmabuf_attach(struct dma_buf *dmabuf, struct dma_buf_attachment *attach)
{
	struct mods_dmabuf_export *export = dmabuf->priv;
	struct pid                *attacher_tgid;

	/* Reject cross-process attach because the BAR mapping is process-owned. */
	attacher_tgid = get_task_pid(current, PIDTYPE_TGID);
	if (unlikely(attacher_tgid != export->owner_tgid)) {
		mods_error_printk("DMA-BUF attach from pid %d rejected; owner pid is %d\n",
				  task_tgid_nr(current), pid_nr(export->owner_tgid));
		put_pid(attacher_tgid);
		return -EPERM;
	}
	put_pid(attacher_tgid);

	if (unlikely(attach->dev->bus != &pci_bus_type)) {
		mods_error_printk("DMA-BUF importer %s is not a PCI device\n",
				  dev_name(attach->dev));
		return -EOPNOTSUPP;
	}
	/* BAR1 has no struct page backing; require a peer-to-peer enabled importer. */
	if (unlikely(!attach->peer2peer)) {
		mods_error_printk("DMA-BUF importer %s did not opt in to peer resources\n",
				  dev_name(attach->dev));
		return -EOPNOTSUPP;
	}

	dmabuf_lock();
	if (unlikely(export->release_guarded)) {
		mods_error_printk("DMA-BUF attach from %s rejected while release guard is held\n",
				  dev_name(attach->dev));
		dmabuf_unlock();
		return -EBUSY;
	}
	if (unlikely(export->attachment_count == U32_MAX)) {
		mods_error_printk("DMA-BUF attachment count overflow for importer %s\n",
				  dev_name(attach->dev));
		dmabuf_unlock();
		return -EOVERFLOW;
	}
	export->attachment_count++;
	dmabuf_unlock();

	return 0;
}

static void mods_dmabuf_detach(struct dma_buf *dmabuf, struct dma_buf_attachment *attach)
{
	struct mods_dmabuf_export *export = dmabuf->priv;

	dmabuf_lock();
	if (unlikely(!export->attachment_count))
		mods_error_printk("DMA-BUF importer %s detached without an active attachment\n",
				  dev_name(attach->dev));
	else
		export->attachment_count--;
	dmabuf_unlock();
}

static void mods_dmabuf_unmap_sg(struct device *dev, struct sg_table *sgt,
				 enum dma_data_direction direction)
{
	struct scatterlist *sg;
	u32                 index;

	for_each_sg(sgt->sgl, sg, sgt->nents, index) {
		if (sg_dma_len(sg))
			dma_unmap_resource(dev, sg_dma_address(sg), sg_dma_len(sg), direction, 0);
	}
}

static unsigned int mods_dmabuf_get_map_size(phys_addr_t addr, u64 remaining,
					      u64 max_segment, u64 boundary_mask)
{
	u64 boundary_remaining = boundary_mask - ((u64)addr & boundary_mask) + 1;
	u64 map_size = min(remaining, max_segment);

	if (boundary_remaining)
		map_size = min(map_size, boundary_remaining);

	return (unsigned int)map_size;
}

static bool mods_dmabuf_crosses_boundary(dma_addr_t addr, unsigned int size, u64 boundary_mask)
{
	u64 start = (u64)addr;
	u64 end   = start + size - 1;

	return ((start ^ end) & ~boundary_mask) != 0;
}

static struct sg_table *mods_dmabuf_map(struct dma_buf_attachment *attach,
					enum dma_data_direction direction)
{
	struct mods_dmabuf_export *export = attach->dmabuf->priv;
	struct scatterlist        *sg;
	struct sg_table           *sgt = NULL;
	u64                        importer_max_segment;
	u64                        max_segment;
	u64                        segment_boundary_mask;
	u64                        nents64 = 0;
	u32                        mapped = 0;
	u32                        index;
	bool                       table_allocated = false;
	int                        err;

	if (unlikely(direction == DMA_NONE))
		return ERR_PTR(-EINVAL);
	if (unlikely(attach->dev->bus != &pci_bus_type)) {
		mods_error_printk("DMA-BUF importer %s is not a PCI device\n",
				  dev_name(attach->dev));
		return ERR_PTR(-EOPNOTSUPP);
	}
	if (unlikely(!attach->peer2peer)) {
		mods_error_printk("DMA-BUF importer %s did not opt in to peer resources\n",
				  dev_name(attach->dev));
		return ERR_PTR(-EOPNOTSUPP);
	}

	mods_debug_printk(DEBUG_MEM, "mapping DMA-BUF size 0x%llx for importer %s (driver %s), direction %u, dma_mask 0x%llx\n",
			  (unsigned long long)export->size,
			  dev_name(attach->dev), dev_driver_string(attach->dev),
			  (unsigned int)direction, attach->dev->dma_mask ?
				(unsigned long long)*attach->dev->dma_mask : 0ULL);

	importer_max_segment = (u64)dma_get_max_seg_size(attach->dev);
	max_segment = min_t(u64, importer_max_segment, (u64)~0U);
	segment_boundary_mask = (u64)dma_get_seg_boundary(attach->dev);
	max_segment -= max_segment % PAGE_SIZE;
	if (unlikely(max_segment < PAGE_SIZE || segment_boundary_mask < PAGE_SIZE - 1))
		return ERR_PTR(-EINVAL);
	mods_debug_printk(DEBUG_MEM_DETAILED, "DMA-BUF importer %s max segment 0x%llx, capped to 0x%llx, boundary mask 0x%llx\n",
			  dev_name(attach->dev), (unsigned long long)importer_max_segment,
			  (unsigned long long)max_segment,
			  (unsigned long long)segment_boundary_mask);

	for (index = 0; index < export->range_count; index++) {
		phys_addr_t phys_addr = (phys_addr_t)export->ranges[index].start;
		u64         remaining = export->ranges[index].size;

		while (remaining) {
			unsigned int map_size = mods_dmabuf_get_map_size(phys_addr, remaining,
									max_segment,
									segment_boundary_mask);

			nents64++;
			if (unlikely(nents64 > MODS_DMABUF_MAX_MAPPED_RANGES)) {
				mods_error_printk("DMA-BUF mapping requires more than %u segments\n",
						  MODS_DMABUF_MAX_MAPPED_RANGES);
				return ERR_PTR(-E2BIG);
			}
			phys_addr += map_size;
			remaining -= map_size;
		}
	}

	sgt = MODS_ZALLOC(*sgt);
	if (unlikely(!sgt)) {
		err = -ENOMEM;
		goto failed;
	}
	atomic_inc(&export->client->num_allocs);

	err = sg_alloc_table(sgt, (unsigned int)nents64, GFP_KERNEL);
	if (unlikely(err))
		goto failed;
	atomic_inc(&export->client->num_allocs);
	table_allocated = true;

	sg = sgt->sgl;
	for (index = 0; index < export->range_count; index++) {
		phys_addr_t phys_addr = (phys_addr_t)export->ranges[index].start;
		u64         remaining = export->ranges[index].size;

		while (remaining) {
			unsigned int map_size = mods_dmabuf_get_map_size(phys_addr, remaining,
									max_segment,
									segment_boundary_mask);
			dma_addr_t dma_addr;

			dma_addr = dma_map_resource(attach->dev, phys_addr, map_size, direction, 0);
			if (unlikely(dma_mapping_error(attach->dev, dma_addr))) {
				err = -EIO;
				goto failed;
			}
			if (unlikely(mods_dmabuf_crosses_boundary(dma_addr, map_size,
								  segment_boundary_mask))) {
				mods_error_printk("DMA-BUF mapping 0x%llx size 0x%x crosses boundary mask 0x%llx\n",
						  (unsigned long long)dma_addr, map_size,
						  (unsigned long long)segment_boundary_mask);
				dma_unmap_resource(attach->dev, dma_addr, map_size, direction, 0);
				err = -EIO;
				goto failed;
			}

			sg_set_page(sg, NULL, map_size, 0);
			sg_dma_address(sg) = dma_addr;
			sg_dma_len(sg) = map_size;
			mapped++;
			mods_debug_printk(DEBUG_MEM_DETAILED, "DMA-BUF importer %s maps resource 0x%llx size 0x%x as DMA address 0x%llx\n",
					  dev_name(attach->dev),
					  (unsigned long long)phys_addr, map_size,
					  (unsigned long long)dma_addr);
			sg = sg_next(sg);
			phys_addr += map_size;
			remaining -= map_size;
		}
	}

	sgt->nents = mapped;
	mods_debug_printk(DEBUG_MEM, "mapped DMA-BUF for importer %s with %u DMA segment(s)\n",
			  dev_name(attach->dev), mapped);
	return sgt;

failed:
	if (table_allocated) {
		sgt->nents = mapped;
		mods_dmabuf_unmap_sg(attach->dev, sgt, direction);
		sg_free_table(sgt);
		atomic_dec(&export->client->num_allocs);
	}
	if (sgt)
		atomic_dec(&export->client->num_allocs);
	kfree(sgt);
	return ERR_PTR(err);
}

static void mods_dmabuf_unmap(struct dma_buf_attachment *attach, struct sg_table *sgt,
			      enum dma_data_direction direction)
{
	struct mods_dmabuf_export *export = attach->dmabuf->priv;

	mods_debug_printk(DEBUG_MEM, "unmapping DMA-BUF from importer %s, direction %u\n",
			  dev_name(attach->dev), (unsigned int)direction);
	mods_dmabuf_unmap_sg(attach->dev, sgt, direction);
	sg_free_table(sgt);
	atomic_dec(&export->client->num_allocs);
	kfree(sgt);
	atomic_dec(&export->client->num_allocs);
}

static void mods_dmabuf_release(struct dma_buf *dmabuf)
{
	struct mods_dmabuf_export *export = dmabuf->priv;
	struct mods_client        *client;
	struct file               *mods_filp;

	if (!export)
		return;

	/* Keep the MODS client alive until the last DMA-BUF reference is released. */
	mods_debug_printk(DEBUG_MEM, "released DMA-BUF export for %04x:%02x:%02x.%x, size 0x%llx, %u range(s)\n",
			  pci_domain_nr(export->dev->bus), export->dev->bus->number,
			  PCI_SLOT(export->dev->devfn), PCI_FUNC(export->dev->devfn),
			  (unsigned long long)export->size, export->range_count);
	client = export->client;
	mods_filp = export->mods_filp;
	dmabuf_lock();
	list_del(&export->list);
	dmabuf_unlock();
	pci_dev_put(export->dev);
	if (export->owner_tgid)
		put_pid(export->owner_tgid);
	kfree(export->ranges);
	atomic_dec(&client->num_allocs);
	kfree(export);
	atomic_dec(&client->num_allocs);
	/* This can invoke mods_krnl_close(), so do it after freeing export state. */
	if (mods_filp)
		fput(mods_filp);
}

static const struct dma_buf_ops mods_dmabuf_ops = {
	.attach        = mods_dmabuf_attach,
	.detach        = mods_dmabuf_detach,
	.map_dma_buf   = mods_dmabuf_map,
	.unmap_dma_buf = mods_dmabuf_unmap,
	.release       = mods_dmabuf_release,
};

static int mods_dmabuf_validate_ranges(struct mods_dmabuf_export *export, resource_size_t bar_start,
				       resource_size_t bar_size)
{
	u64 total = 0;
	u32 index;

	if (unlikely(!export->size || (u64)(size_t)export->size != export->size ||
		     !PAGE_ALIGNED(export->size)))
		return -EINVAL;

	for (index = 0; index < export->range_count; index++) {
		u64 start = export->ranges[index].start;
		u64 size  = export->ranges[index].size;
		u32 previous;

		if (unlikely(!size || (u64)(phys_addr_t)start != start || !PAGE_ALIGNED(start) ||
			     !PAGE_ALIGNED(size) || start + size < start ||
			     total + size < total || start < bar_start ||
			     size > bar_size || start - bar_start > bar_size - size))
			return -EINVAL;

		for (previous = 0; previous < index; previous++) {
			u64 previous_start = export->ranges[previous].start;
			u64 previous_end = previous_start + export->ranges[previous].size;

			if (unlikely(start < previous_end && previous_start < start + size))
				return -EINVAL;
		}

		total += size;
	}

	return total == export->size ? 0 : -EINVAL;
}

static int mods_dmabuf_create(struct mods_client *client, struct file *filp,
			      struct MODS_DMABUF_EXPORT_MEMORY *p, struct dma_buf **out_dmabuf)
{
	struct mods_dmabuf_export *export = NULL;
	struct dma_buf            *dmabuf;
	struct pci_dev            *gpu_dev = NULL;
	unsigned int               bar_resource_offset;
	resource_size_t            bar_start;
	resource_size_t            bar_size;
	size_t                     ranges_size;
	struct file               *mods_filp = NULL;
	int                        err;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	LOG_ENT();
	dmabuf_lock();

	*out_dmabuf   = NULL;
	p->dma_buf_fd = -1;

	if (unlikely(p->flags || p->reserved || !p->range_count ||
		     p->range_count > MODS_DMABUF_MAX_RANGES ||
		     p->bar_index != MODS_DMABUF_FB_BAR_INDEX)) {
		err = -EINVAL;
		goto failed;
	}

	err = mods_find_pci_dev(client, &p->pci_device, &gpu_dev);
	if (unlikely(err))
		goto failed;

	if (unlikely(!mods_dmabuf_is_nvidia_gpu(gpu_dev))) {
		cl_error("DMA-BUF export device %04x:%02x:%02x.%x is not an NVIDIA GPU\n",
			 pci_domain_nr(gpu_dev->bus), gpu_dev->bus->number,
			 PCI_SLOT(gpu_dev->devfn), PCI_FUNC(gpu_dev->devfn));
		err = -EINVAL;
		goto failed;
	}

	if (unlikely(mods_dmabuf_pci_remove_pending(gpu_dev) ||
		     mods_dmabuf_pci_reset_pending(gpu_dev))) {
		cl_error("DMA-BUF export device %04x:%02x:%02x.%x is unavailable\n",
			 pci_domain_nr(gpu_dev->bus), gpu_dev->bus->number,
			 PCI_SLOT(gpu_dev->devfn), PCI_FUNC(gpu_dev->devfn));
		err = -EBUSY;
		goto failed;
	}

	err = mods_dmabuf_validate_owner(client, gpu_dev);
	if (unlikely(err)) {
		cl_error("client %u does not own enabled GPU %04x:%02x:%02x.%x\n",
			 client->client_id, pci_domain_nr(gpu_dev->bus),
			 gpu_dev->bus->number, PCI_SLOT(gpu_dev->devfn), PCI_FUNC(gpu_dev->devfn));
		goto failed;
	}

	err = mods_pci_bar_index_to_resource(gpu_dev, p->bar_index, &bar_resource_offset);
	if (unlikely(err || bar_resource_offset > PCI_STD_RESOURCE_END)) {
		err = -EINVAL;
		goto failed;
	}

	bar_start = pci_resource_start(gpu_dev, bar_resource_offset);
	bar_size  = pci_resource_len(gpu_dev, bar_resource_offset);
	if (unlikely(!bar_size ||
		     !(pci_resource_flags(gpu_dev, bar_resource_offset) & IORESOURCE_MEM))) {
		err = -EINVAL;
		goto failed;
	}

	ranges_size = (size_t)p->range_count * sizeof(*export->ranges);

	export = MODS_ZALLOC(*export);
	if (unlikely(!export)) {
		err = -ENOMEM;
		goto failed;
	}
	atomic_inc(&client->num_allocs);
	export->client = client;

	export->ranges = kzalloc(ranges_size, GFP_KERNEL | __GFP_NORETRY);
	if (unlikely(!export->ranges)) {
		err = -ENOMEM;
		goto failed;
	}
	atomic_inc(&client->num_allocs);

	memcpy(export->ranges, p->ranges, ranges_size);

	export->size           = p->size;
	export->range_count    = p->range_count;
	export->dev            = gpu_dev;
	get_file(filp);
	export->mods_filp = filp;
	export->owner_tgid = get_task_pid(current, PIDTYPE_TGID);

	err = mods_dmabuf_validate_ranges(export, bar_start, bar_size);
	if (unlikely(err))
		goto failed;
	cl_debug(DEBUG_MEM, "validated DMA-BUF ranges against BAR1 base 0x%llx size 0x%llx\n",
		 (unsigned long long)bar_start, (unsigned long long)bar_size);

	exp_info.ops      = &mods_dmabuf_ops;
	exp_info.size     = (size_t)export->size;
	exp_info.flags    = O_RDWR | O_CLOEXEC;
	exp_info.priv     = export;
	exp_info.exp_name = "mods_dmabuf";

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		err = PTR_ERR(dmabuf);
		goto failed;
	}
	list_add(&export->list, &mods_dmabuf_exports);
	/* mods_dmabuf_release() now owns the pci_dev reference. */
	gpu_dev = NULL;
	export = NULL;

	*out_dmabuf = dmabuf;
	cl_debug(DEBUG_MEM, "exported DMA-BUF, size 0x%llx, %u range(s)\n",
		 (unsigned long long)p->size, p->range_count);
	err = 0;

failed:
	if (export) {
		mods_filp = export->mods_filp;
		if (export->owner_tgid)
			put_pid(export->owner_tgid);
		if (export->ranges)
			atomic_dec(&client->num_allocs);
		kfree(export->ranges);
		kfree(export);
		atomic_dec(&client->num_allocs);
	}
	if (gpu_dev)
		pci_dev_put(gpu_dev);
	/* fput() can invoke mods_krnl_close(), so call it after freeing export. */
	if (mods_filp)
		fput(mods_filp);
	dmabuf_unlock();
	LOG_EXT();
	return err;
}

int esc_mods_dmabuf_export_memory(struct mods_client *client, struct file *filp,
				  void __user *user_arg, void *arg_copy, size_t arg_size)
{
	struct MODS_DMABUF_EXPORT_MEMORY *p = arg_copy;
	struct dma_buf                   *dmabuf = NULL;
	int                               fd;
	int                               err;

	cl_debug(DEBUG_IOCTL, "ioctl(MODS_ESC_DMABUF_EXPORT_MEMORY)\n");

	if (arg_size != sizeof(*p)) {
		cl_error("invalid parameter passed to ioctl MODS_ESC_DMABUF_EXPORT_MEMORY\n");
		return -EINVAL;
	}

	err = mods_dmabuf_create(client, filp, p, &dmabuf);
	if (err)
		return err;

	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (unlikely(fd < 0)) {
		dma_buf_put(dmabuf);
		return fd;
	}

	p->dma_buf_fd = fd;

	if (copy_to_user(user_arg, p, sizeof(*p))) {
		put_unused_fd(fd);
		dma_buf_put(dmabuf);
		cl_error("copying DMA-BUF export result to user space failed\n");
		return -EFAULT;
	}

	fd_install(fd, dmabuf->file);
	cl_debug(DEBUG_MEM, "installed DMA-BUF fd %d\n", fd);
	return 0;
}

int esc_mods_dmabuf_acquire_release_guard(struct mods_client *client,
					  struct MODS_DMABUF_ACQUIRE_RELEASE_GUARD *p)
{
	struct mods_dmabuf_export *export;
	struct dma_buf            *dmabuf;
	int                        err = 0;

	if (unlikely(p->dma_buf_fd < 0 || p->reserved))
		return -EINVAL;

	dmabuf = dma_buf_get(p->dma_buf_fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	if (unlikely(dmabuf->ops != &mods_dmabuf_ops || !dmabuf->priv)) {
		err = -EINVAL;
		goto done;
	}

	export = dmabuf->priv;
	dmabuf_lock();
	if (unlikely(export->client != client || export->owner_tgid != task_tgid(current)))
		err = -EPERM;
	else if (export->attachment_count)
		err = -EBUSY;
	else
		export->release_guarded = true;
	dmabuf_unlock();

done:
	dma_buf_put(dmabuf);
	return err;
}

#endif
