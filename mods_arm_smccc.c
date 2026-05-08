// SPDX-License-Identifier: GPL-2.0-only
/* SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION.  All rights reserved. */

#include "mods_internal.h"

#if defined(MODS_HAS_ARM_SMCCC)

#include <linux/arm-smccc.h>

#define SMC_RMI_CALL(func)                              \
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,         \
			   ARM_SMCCC_SMC_64,            \
			   ARM_SMCCC_OWNER_STANDARD,    \
			   (func))

#define SMC_RMI_GRANULE_DELEGATE        SMC_RMI_CALL(0x0151)
#define SMC_RMI_GRANULE_UNDELEGATE      SMC_RMI_CALL(0x0152)

#define SMC_RMI_QDEV_DESTROY            SMC_RMI_CALL(0x02CE)
#define SMC_RMI_QDEV_CREATE             SMC_RMI_CALL(0x02CF)

#define RMI_QDEV_FLAGS_LINK_IDE         (1 << 0)
#define RMI_QDEV_FLAGS_C2C              (1 << 1)
#define RMI_QDEV_FLAGS_SEL_IDE          (1 << 2)

struct rmi_qdev_params {
	union {
		struct {
			unsigned long flags;
			unsigned long dev_id;
			unsigned long segment_id;
			unsigned long root_id;
			unsigned long rid_base;
			unsigned long rid_top;
		};
	};
};

static unsigned long rmi_granule_delegate(unsigned long phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_GRANULE_DELEGATE, phys, &res);
	return res.a0;
}

static unsigned long rmi_granule_undelegate(unsigned long phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_GRANULE_UNDELEGATE, phys, &res);
	return res.a0;
}

static unsigned long rmi_qdev_create(unsigned long qdev_phys, unsigned long qdev_params_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_QDEV_CREATE, qdev_phys, qdev_params_phys, &res);
	return res.a0;
}

static unsigned long rmi_qdev_destroy(unsigned long qdev_phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_QDEV_DESTROY, qdev_phys, &res);
	return res.a0;
}

int mods_qdev_enable(struct pci_dev *epdev,
		     u8              qual_mode,
		     void          **p_qdev)
{
	struct rmi_qdev_params *params = NULL;
	struct pci_dev         *rpdev;
	phys_addr_t             qdev_phys;
	unsigned long           smccc_ret;
	int                     err = 0;
	int                     domain;

	LOG_ENT();

	*p_qdev = NULL;

	rpdev = pcie_find_root_port(epdev);
	if (unlikely(rpdev == NULL)) {
		err = -ENODEV;
		goto cleanup;
	}

	params = (struct rmi_qdev_params *)get_zeroed_page(GFP_KERNEL);
	if (unlikely(!params)) {
		err = -ENOMEM;
		goto cleanup;
	}

	domain = pci_domain_nr(epdev->bus);
	if (domain < 0)
		domain = 0;

	params->dev_id     = pci_dev_id(epdev);
	params->rid_base   = pci_dev_id(epdev);
	params->rid_top    = pci_dev_id(epdev) + 1;
	params->root_id    = pci_dev_id(rpdev);
	params->segment_id = domain;
	params->flags      = (qual_mode & MODS_QUAL_MODE_LINK_IDE) ? RMI_QDEV_FLAGS_LINK_IDE : 0;
	params->flags      |= (qual_mode & MODS_QUAL_MODE_C2C) ? RMI_QDEV_FLAGS_C2C : 0;
	params->flags      |= (qual_mode & MODS_QUAL_MODE_SEL_IDE) ? RMI_QDEV_FLAGS_SEL_IDE : 0;

	*p_qdev = (void *)get_zeroed_page(GFP_KERNEL);
	if (unlikely(!*p_qdev)) {
		err = -ENOMEM;
		goto cleanup;
	}

	qdev_phys = virt_to_phys(*p_qdev);
	smccc_ret = rmi_granule_delegate(qdev_phys);
	if (unlikely(smccc_ret)) {
		mods_error_printk("failed to delegate qdev page for %04x:%02x:%02x.%x\n",
			pci_domain_nr(epdev->bus),
			epdev->bus->number,
			PCI_SLOT(epdev->devfn),
			PCI_FUNC(epdev->devfn));
		err = -ENODEV;
		goto cleanup;
	}

	smccc_ret = rmi_qdev_create(qdev_phys, virt_to_phys(params));
	if (unlikely(smccc_ret)) {
		mods_error_printk("failed to create qdev for %04x:%02x:%02x.%x\n",
			pci_domain_nr(epdev->bus),
			epdev->bus->number,
			PCI_SLOT(epdev->devfn),
			PCI_FUNC(epdev->devfn));
		smccc_ret = rmi_granule_undelegate(qdev_phys);
		if (smccc_ret) {
			mods_warning_printk("failed to undelegate granule, page leaked\n");
			*p_qdev = NULL;
		}
		err = -ENODEV;
		goto cleanup;
	}

cleanup:
	if (err && *p_qdev) {
		free_page((unsigned long)*p_qdev);
		*p_qdev = NULL;
	}
	if (params)
		free_page((unsigned long)params);

	LOG_EXT();

	return err;
}

int mods_qdev_disable(void *qdev)
{
	unsigned long smccc_ret;
	phys_addr_t qdev_phys;

	if (!qdev)
		return 0;

	qdev_phys = virt_to_phys(qdev);

	smccc_ret = rmi_qdev_destroy(qdev_phys);
	if (unlikely(smccc_ret)) {
		mods_warning_printk("failed to destroy qdev, page leaked\n");
		return -EBUSY;
	}

	smccc_ret = rmi_granule_undelegate(qdev_phys);
	if (unlikely(smccc_ret)) {
		mods_warning_printk("failed to undelegate granule, page leaked\n");
		return -EBUSY;
	}

	free_page((unsigned long)qdev);

	return 0;
}

int esc_mods_set_qual_mode(struct mods_client        *client,
			   struct MODS_SET_QUAL_MODE *p)
{
	int                  err = OK;
	struct pci_dev      *dev = NULL;
	struct en_dev_entry *dpriv;

	LOG_ENT();

	if (unlikely(mods_get_force_qual_mode())) {
		cl_error("force qual mode is set, cannot set qual mode\n");
		err = -EINVAL;
		goto cleanup;
	}

	if (p->mode & ~(MODS_QUAL_MODE_LINK_IDE | MODS_QUAL_MODE_C2C | MODS_QUAL_MODE_SEL_IDE)) {
		cl_error("invalid qual mode value: 0x%x\n", p->mode);
		err = -EINVAL;
		goto cleanup;
	}

	err = mods_find_pci_dev(client, &p->pci_device, &dev);
	if (unlikely(err)) {
		if (err == -ENODEV)
			cl_error("dev %04x:%02x:%02x.%x not found\n",
				 p->pci_device.domain,
				 p->pci_device.bus,
				 p->pci_device.device,
				 p->pci_device.function);
		goto cleanup;
	}

	dpriv = pci_get_drvdata(dev);
	if (unlikely(!dpriv)) {
		cl_error("driver data is not set for %04x:%02x:%02x.%x\n",
			 p->pci_device.domain,
			 p->pci_device.bus,
			 p->pci_device.device,
			 p->pci_device.function);
		err = -EINVAL;
		goto cleanup;
	}

	mutex_lock(mods_get_irq_mutex());

	if (unlikely(is_valid_client_id(dpriv->client_id))) {
		mutex_unlock(mods_get_irq_mutex());
		cl_error("device %04x:%02x:%02x.%x is already enabled, cannot change qual mode\n",
			 p->pci_device.domain,
			 p->pci_device.bus,
			 p->pci_device.device,
			 p->pci_device.function);
		err = -EINVAL;
		goto cleanup;
	}

	dpriv->qual_mode = p->mode;

	mutex_unlock(mods_get_irq_mutex());

cleanup:
	if (dev)
		pci_dev_put(dev);

	LOG_EXT();

	return err;
}

#endif /* MODS_HAS_ARM_SMCCC */
