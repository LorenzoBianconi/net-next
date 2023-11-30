// SPDX-License-Identifier: GPL-2.0
/*
 * Airoha PCIe host controller driver.
 *
 * Copyright (C) 2023 Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pm_runtime.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_pci.h>
#include <linux/pci.h>
#include <linux/version.h>

#include "../pci.h"

/* PCIe shared registers */
#define PCIE_SYS_CFG		0x00
#define PCIE_INT_ENABLE		0x0c
#define PCIE_CFG_ADDR		0x20
#define PCIE_CFG_DATA		0x24

/* PCIe per port registers */
#define PCIE_BAR0_SETUP		0x10
#define PCIE_CLASS		0x34
#define PCIE_LINK_STATUS	0x50

#define PCIE_PORT_INT_EN(x)	BIT(20 + (x))
#define PCIE_PORT_PERST(x)	BIT(1 + (x))
#define PCIE_PORT_LINKUP	BIT(0)
#define PCIE_BAR_MAP_MAX	GENMASK(31, 16)

#define PCIE_BAR_ENABLE		BIT(0)
#define PCIE_REVISION_ID	BIT(0)
#define PCIE_CLASS_CODE		(0x60400 << 8)
#define PCIE_CONF_REG(regn)	(((regn) & GENMASK(7, 2)) | \
				((((regn) >> 8) & GENMASK(3, 0)) << 24))
#define PCIE_CONF_FUN(fun)	(((fun) << 8) & GENMASK(10, 8))
#define PCIE_CONF_DEV(dev)	(((dev) << 11) & GENMASK(15, 11))
#define PCIE_CONF_BUS(bus)	(((bus) << 16) & GENMASK(23, 16))
#define PCIE_CONF_ADDR(regn, fun, dev, bus) \
	(PCIE_CONF_REG(regn) | PCIE_CONF_FUN(fun) | \
	 PCIE_CONF_DEV(dev) | PCIE_CONF_BUS(bus))

/* MediaTek specific configuration registers */
#define PCIE_FTS_NUM		0x70c
#define PCIE_FTS_NUM_MASK	GENMASK(15, 8)
#define PCIE_FTS_NUM_L0(x)	((x) & 0xff << 8)

#define PCIE_FC_CREDIT		0x73c
#define PCIE_FC_CREDIT_MASK	(GENMASK(31, 31) | GENMASK(28, 16))
#define PCIE_FC_CREDIT_VAL(x)	((x) << 16)

/* PCIe V2 share registers */
#define PCIE_SYS_CFG_V2		0x0
#define PCIE_CSR_LTSSM_EN(x)	BIT(0 + (x) * 8)
#define PCIE_CSR_ASPM_L1_EN(x)	BIT(1 + (x) * 8)

/* PCIe V2 per-port registers */
#define PCIE_MSI_VECTOR		0x0c0

#define K_GBL_1			0x000
#define K_CONF_FUNC0_1		0x104

#define PCIE_INT_MASK		0x420
#define INTX_MASK		GENMASK(19, 16)
#define INTX_SHIFT		16
#define PCIE_INT_STATUS		0x424
#define MSI_STATUS		BIT(23)
#define PCIE_IMSI_STATUS	0x42c
#define PCIE_IMSI_ADDR		0x430
#define MSI_MASK		BIT(23)

#define PCIE_AHB_TRANS_BASE0_L	0x438
#define PCIE_AHB_TRANS_BASE0_H	0x43c
#define AHB2PCIE_SIZE(x)	((x) & GENMASK(4, 0))
#define PCIE_AXI_WINDOW0	0x448
#define WIN_ENABLE		BIT(7)

/* PCIe V2 configuration transaction header */
#define PCIE_CFG_HEADER0	0x460
#define PCIE_CFG_HEADER1	0x464
#define PCIE_CFG_HEADER2	0x468
#define PCIE_CFG_WDATA		0x470
#define PCIE_APP_TLP_REQ	0x488
#define PCIE_CFG_RDATA		0x48c
#define APP_CFG_REQ		BIT(0)
#define APP_CPL_STATUS		GENMASK(7, 5)

#define CFG_WRRD_TYPE_0		4
#define CFG_WRRD_TYPE_1		5
#define CFG_WR_FMT		2
#define CFG_RD_FMT		0

#define CFG_DW0_LENGTH(length)	((length) & GENMASK(9, 0))
#define CFG_DW0_TYPE(type)	(((type) << 24) & GENMASK(28, 24))
#define CFG_DW0_FMT(fmt)	(((fmt) << 29) & GENMASK(31, 29))
#define CFG_DW2_REGN(regn)	((regn) & GENMASK(11, 2))
#define CFG_DW2_FUN(fun)	(((fun) << 16) & GENMASK(18, 16))
#define CFG_DW2_DEV(dev)	(((dev) << 19) & GENMASK(23, 19))
#define CFG_DW2_BUS(bus)	(((bus) << 24) & GENMASK(31, 24))
#define CFG_HEADER_DW0(type, fmt) \
	(CFG_DW0_LENGTH(1) | CFG_DW0_TYPE(type) | CFG_DW0_FMT(fmt))
#define CFG_HEADER_DW1(where, size) \
	(GENMASK(((size) - 1), 0) << ((where) & 0x3))
#define CFG_HEADER_DW2(regn, fun, dev, bus) \
	(CFG_DW2_REGN(regn) | CFG_DW2_FUN(fun) | \
	CFG_DW2_DEV(dev) | CFG_DW2_BUS(bus))

#define PCIE_RST_CTRL		0x510
#define PCIE_PHY_RSTB		BIT(0)
#define PCIE_PIPE_SRSTB		BIT(1)
#define PCIE_MAC_SRSTB		BIT(2)
#define PCIE_CRSTB		BIT(3)
#define PCIE_PERSTB		BIT(8)
#define PCIE_LINKDOWN_RST_EN	GENMASK(15, 13)
#define PCIE_LINK_STATUS_V2	0x804
#define PCIE_PORT_LINKUP_V2	BIT(10)

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,1,0)
static bool of_property_present(const struct device_node *np, const char *propname)
{
	return of_property_read_bool(np, propname);
}
#endif

/**
 * struct airoha_pcie - PCIe host information
 * @dev: pointer to PCIe device
 * @clk: pointer to transaction/data link layer clock
 * @ports: PCIe port list
 */
struct airoha_pcie {
	struct device *dev;
	struct clk *clk;
	struct list_head ports;
};

/**
 * struct airoha_pcie_port - PCIe port information
 * @pcie: pointer to PCIe host info
 * @list: port list
 * @base: IO mapped register base
 * @slot: port slot
 * @irq: GIC irq
 */
struct airoha_pcie_port {
	struct airoha_pcie *pcie;
	struct list_head list;
	void __iomem *base;
	u32 slot;
	int irq;
};

static int airoha_pcie_check_config_status(struct airoha_pcie_port *port)
{
	u32 val;
	int err;

	err = readl_poll_timeout_atomic(port->base + PCIE_APP_TLP_REQ, val,
					!(val & APP_CFG_REQ), 10,
					100 * USEC_PER_MSEC);
	if (err)
		return PCIBIOS_SET_FAILED;

	if (readl(port->base + PCIE_APP_TLP_REQ) & APP_CPL_STATUS)
		return PCIBIOS_SET_FAILED;

	return PCIBIOS_SUCCESSFUL;
}

static int airoha_pcie_hw_read_config(struct airoha_pcie_port *port, u32 bus,
				      u32 devfn, int where, int size,
				      u32 *val)
{
	u32 tmp;

	/* Write PCIe configuration transaction header for Cfgrd */
	writel(CFG_HEADER_DW0(CFG_WRRD_TYPE_0, CFG_RD_FMT),
	       port->base + PCIE_CFG_HEADER0);
	writel(CFG_HEADER_DW1(where, size), port->base + PCIE_CFG_HEADER1);
	writel(CFG_HEADER_DW2(where, PCI_FUNC(devfn), PCI_SLOT(devfn), bus),
	       port->base + PCIE_CFG_HEADER2);

	/* Trigger h/w to transmit Cfgrd TLP */
	tmp = readl(port->base + PCIE_APP_TLP_REQ) | APP_CFG_REQ;
	writel(tmp, port->base + PCIE_APP_TLP_REQ);

	/* Check completion status */
	if (airoha_pcie_check_config_status(port)) {
		*val = ~0;
		return PCIBIOS_SET_FAILED;
	}

	/* Read cpld payload of Cfgrd */
	*val = readl(port->base + PCIE_CFG_RDATA);
	if (size == 1)
		*val = (*val >> (8 * (where & 3))) & 0xff;
	else if (size == 2)
		*val = (*val >> (8 * (where & 3))) & 0xffff;

	return PCIBIOS_SUCCESSFUL;
}

static int airoha_pcie_hw_write_config(struct airoha_pcie_port *port, u32 bus,
				       u32 devfn, int where, int size,
				       u32 val)
{
	/* Write PCIe configuration transaction header for Cfgwr */
	writel(CFG_HEADER_DW0(CFG_WRRD_TYPE_0, CFG_WR_FMT),
	       port->base + PCIE_CFG_HEADER0);
	writel(CFG_HEADER_DW1(where, size), port->base + PCIE_CFG_HEADER1);
	writel(CFG_HEADER_DW2(where, PCI_FUNC(devfn), PCI_SLOT(devfn), bus),
	       port->base + PCIE_CFG_HEADER2);

	val = val << 8 * (where & 3);
	/* Write Cfgwr data */
	writel(val, port->base + PCIE_CFG_WDATA);

	/* Trigger h/w to transmit Cfgwr TLP */
	val = readl(port->base + PCIE_APP_TLP_REQ) | APP_CFG_REQ;
	writel(val, port->base + PCIE_APP_TLP_REQ);

	/* Check completion status */
	return airoha_pcie_check_config_status(port);
}

static struct airoha_pcie_port *
airoha_pcie_find_port(struct pci_bus *bus, unsigned int devfn)
{
	struct airoha_pcie *pcie = bus->sysdata;
	struct airoha_pcie_port *port;
	struct pci_dev *dev;
	struct pci_bus *pbus;

	list_for_each_entry(port, &pcie->ports, list) {
		if (!bus->number && port->slot == PCI_SLOT(devfn)) {
			return port;
		} else if (bus->number) {
			pbus = bus;
			do {
				dev = pbus->self;
				if (port->slot == PCI_SLOT(dev->devfn))
					return port;

				pbus = dev->bus;
			} while (dev->bus->number);
		}
	}

	return NULL;
}

static int airoha_pcie_config_read(struct pci_bus *bus, unsigned int devfn,
				   int where, int size, u32 *val)
{
	struct airoha_pcie_port *port;

	port = airoha_pcie_find_port(bus, devfn);
	if (!port) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	return airoha_pcie_hw_read_config(port, bus->number, devfn, where,
					  size, val);
}

static int airoha_pcie_config_write(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 val)
{
	struct airoha_pcie_port *port;

	port = airoha_pcie_find_port(bus, devfn);
	if (!port)
		return PCIBIOS_DEVICE_NOT_FOUND;

	return airoha_pcie_hw_write_config(port, bus->number, devfn, where,
					   size, val);
}

static struct pci_ops airoha_pcie_ops = {
	.read  = airoha_pcie_config_read,
	.write = airoha_pcie_config_write,
};

static int airoha_pcie_alloc_port(struct airoha_pcie *pcie,
				  struct device_node *node, int slot)
{
	struct device *dev = pcie->dev;
	struct platform_device *pdev = to_platform_device(dev);
	struct airoha_pcie_port *port;
	int irq;

	port = devm_kzalloc(dev, sizeof(*port), GFP_KERNEL);
	if (!port)
		return -ENOMEM;

	port->base = devm_platform_get_and_ioremap_resource(pdev, slot, NULL);
	if (IS_ERR(port->base)) {
		dev_err(dev, "failed to map port%d base\n", slot);
		return PTR_ERR(port->base);
	}

	irq = platform_get_irq(pdev, slot);
	if (irq < 0)
		return irq;

	port->slot = slot;
	port->pcie = pcie;
	port->irq = irq;

	INIT_LIST_HEAD(&port->list);
	list_add_tail(&port->list, &pcie->ports);

	return 0;
}

static void airoha_pcie_free_port(struct airoha_pcie_port *port)
{
	struct airoha_pcie *pcie = port->pcie;
	struct device *dev = pcie->dev;

	devm_iounmap(dev, port->base);
	list_del(&port->list);
	devm_kfree(dev, port);
}

static int airoha_pcie_startup_port(struct airoha_pcie_port *port)
{
	struct airoha_pcie *pcie = port->pcie;
	struct pci_host_bridge *host = pci_host_bridge_from_priv(pcie);
	struct resource_entry *entry;
	struct resource *mem = NULL;
	u32 val;

	entry = resource_list_first_type(&host->windows, IORESOURCE_MEM);
	if (entry)
		mem = entry->res;
	if (!mem)
		return -EINVAL;

	/* reset for linkup */
	writel(0x804201, port->base + K_GBL_1);
	writel(0x06040001, port->base + K_CONF_FUNC0_1);

	/* 100ms timeout value should be enough for Gen1/2 training */
	readl_poll_timeout(port->base + PCIE_LINK_STATUS_V2, val,
			   !!(val & PCIE_PORT_LINKUP_V2), 20,
			   100 * USEC_PER_MSEC);

	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		/* Set MSI mask */
		phys_addr_t msg_addr = virt_to_phys(port->base + PCIE_MSI_VECTOR);

		val = lower_32_bits(msg_addr);
		writel(val, port->base + PCIE_IMSI_ADDR);
		val = readl(port->base + PCIE_INT_MASK) & ~MSI_MASK;
		writel(val, port->base + PCIE_INT_MASK);
	}

	/* Set INTx mask */
	val = readl(port->base + PCIE_INT_MASK) & ~INTX_MASK;
	writel(val, port->base + PCIE_INT_MASK);

	/* Set AHB to PCIe translation windows */
	val = lower_32_bits(mem->start) |
	      AHB2PCIE_SIZE(fls(resource_size(mem)));
	writel(val, port->base + PCIE_AHB_TRANS_BASE0_L);

	val = upper_32_bits(mem->start);
	writel(val, port->base + PCIE_AHB_TRANS_BASE0_H);

	/* Set PCIe to AXI translation memory space.*/
	writel(WIN_ENABLE, port->base + PCIE_AXI_WINDOW0);

	return 0;
}

static int airoha_pcie_enable_port(struct airoha_pcie_port *port)
{
	int err;

	err = airoha_pcie_startup_port(port);
	if (err)
		airoha_pcie_free_port(port);

	return err;
}

static int airoha_pcie_subsys_powerup(struct airoha_pcie *pcie)
{
	struct device *dev = pcie->dev;
	int err;

	pcie->clk = devm_clk_get(dev, "pcie");
	if (IS_ERR(pcie->clk)) {
		dev_err(dev, "failed to get pcie clock\n");
		return PTR_ERR(pcie->clk);
	}

	err = clk_prepare_enable(pcie->clk);
	if (err) {
		dev_err(dev, "failed to enable pcie clock\n");
		return err;
	}

	pm_runtime_enable(dev);
	pm_runtime_get_sync(dev);

	return 0;
}

static void airoha_pcie_subsys_powerdown(struct airoha_pcie *pcie)
{
	struct device *dev = pcie->dev;

	clk_disable_unprepare(pcie->clk);
	pm_runtime_put_sync(dev);
	pm_runtime_disable(dev);
}

static int airoha_pcie_setup(struct airoha_pcie *pcie)
{
	struct device *dev = pcie->dev;
	struct device_node *node = dev->of_node;
	struct airoha_pcie_port *port, *tmp;
	int slot, err;

	slot = of_get_pci_domain_nr(node);
	if (slot < 0) {
		struct device_node *child;

		for_each_available_child_of_node(node, child) {
			err = of_pci_get_devfn(child);
			if (err < 0) {
				dev_err(dev, "failed to get devfn: %d\n", err);
				of_node_put(child);
				return err;
			}

			slot = PCI_SLOT(err);
			err = airoha_pcie_alloc_port(pcie, child, slot);
			if (err) {
				of_node_put(child);
				return err;
			}
		}
	} else {
		err = airoha_pcie_alloc_port(pcie, node, slot);
		if (err)
			return err;
	}

	if (list_empty(&pcie->ports)) {
		dev_info(dev, "no ports found\n");
		return 0;
	}

	err = airoha_pcie_subsys_powerup(pcie);
	if (err)
		return err;

	list_for_each_entry_safe(port, tmp, &pcie->ports, list) {
		err = airoha_pcie_enable_port(port);
		if (err)
			goto error_enable_port;
	}

	return 0;

error_enable_port:
	airoha_pcie_subsys_powerdown(pcie);
	return err;
}

static int airoha_pcie_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct airoha_pcie *pcie = dev->bus->sysdata;
	struct airoha_pcie_port *port;

	list_for_each_entry(port, &pcie->ports, list) {
		if (port->slot == slot)
			return port->irq;
	}

	return -EINVAL;
}

static void airoha_pcie_release_resources(struct airoha_pcie *pcie)
{
	struct airoha_pcie_port *port, *tmp;

	airoha_pcie_subsys_powerdown(pcie);
	list_for_each_entry_safe(port, tmp, &pcie->ports, list)
		airoha_pcie_free_port(port);
}

static int airoha_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct pci_host_bridge *host;
	struct airoha_pcie *pcie;
	int err;

	host = devm_pci_alloc_host_bridge(dev, sizeof(*pcie));
	if (!host)
		return -ENOMEM;

	pcie = pci_host_bridge_priv(host);
	pcie->dev = dev;
	platform_set_drvdata(pdev, pcie);
	INIT_LIST_HEAD(&pcie->ports);

	err = airoha_pcie_setup(pcie);
	if (err)
		return err;

	host->ops = &airoha_pcie_ops;
	host->sysdata = pcie;
	host->map_irq = airoha_pcie_map_irq;
	/* FIXME is MSI supported ?? */
	host->msi_domain = true;

	err = pci_host_probe(host);
	if (err)
		airoha_pcie_release_resources(pcie);

	return err;
}

static void airoha_pcie_remove(struct platform_device *pdev)
{
	struct airoha_pcie *pcie = platform_get_drvdata(pdev);
	struct pci_host_bridge *host = pci_host_bridge_from_priv(pcie);

	pci_stop_root_bus(host->bus);
	pci_remove_root_bus(host->bus);
	pci_free_resource_list(&host->windows);

	airoha_pcie_release_resources(pcie);
}

static const struct of_device_id airoha_pcie_ids[] = {
	{ .compatible = "airoha,en7523-pcie" },
	{},
};
MODULE_DEVICE_TABLE(of, airoha_pcie_ids);

static struct platform_driver airoha_pcie_driver = {
	.probe = airoha_pcie_probe,
	.remove_new = airoha_pcie_remove,
	.driver = {
		.name = "airoha-pcie",
		.of_match_table = airoha_pcie_ids,
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(airoha_pcie_driver);

MODULE_AUTHOR("Lorenzo Bianconi <lorenzo@kernel.org>");
MODULE_LICENSE("GPL v2");
