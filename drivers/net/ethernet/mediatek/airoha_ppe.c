// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 AIROHA Inc
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/devcoredump.h>
#include <linux/firmware.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/of_reserved_mem.h>
#include <linux/rhashtable.h>
#include <net/ipv6.h>

#include "airoha_regs.h"
#include "airoha_eth.h"

#define NPU_EN7581_FIRMWARE_DATA		"airoha/en7581_npu_data.bin"
#define NPU_EN7581_FIRMWARE_RV32		"airoha/en7581_npu_rv32.bin"
#define NPU_EN7581_FIRMWARE_RV32_MAX_SIZE	0x200000
#define NPU_EN7581_FIRMWARE_DATA_MAX_SIZE	0x10000
#define NPU_DUMP_SIZE				512

#define REG_NPU_LOCAL_SRAM		0x0

#define NPU_PC_BASE_ADDR		0x305000
#define REG_PC_DBG(_n)			(0x305000 + ((_n) * 0x100))

#define NPU_CLUSTER_BASE_ADDR		0x306000

#define REG_CR_BOOT_TRIGGER		(NPU_CLUSTER_BASE_ADDR + 0x000)
#define REG_CR_BOOT_CONFIG		(NPU_CLUSTER_BASE_ADDR + 0x004)
#define REG_CR_BOOT_BASE(_n)		(NPU_CLUSTER_BASE_ADDR + 0x020 + ((_n) << 2))

#define NPU_MBOX_BASE_ADDR		0x30c000

#define REG_CR_MBOX_INT_STATUS		(NPU_MBOX_BASE_ADDR + 0x000)
#define MBOX_INT_STATUS_MASK		BIT(8)

#define REG_CR_MBOX_INT_MASK(_n)	(NPU_MBOX_BASE_ADDR + 0x004 + ((_n) << 2))
#define REG_CR_MBQ0_CTRL(_n)		(NPU_MBOX_BASE_ADDR + 0x030 + ((_n) << 2))
#define REG_CR_MBQ8_CTRL(_n)		(NPU_MBOX_BASE_ADDR + 0x0b0 + ((_n) << 2))
#define REG_CR_NPU_MIB(_n)		(NPU_MBOX_BASE_ADDR + 0x140 + ((_n) << 2))

#define NPU_TIMER_BASE_ADDR		0x310100
#define REG_WDT_TIMER_CTRL(_n)		(NPU_TIMER_BASE_ADDR + ((_n) * 0x100))
#define WDT_EN_MASK			BIT(25)
#define WDT_INTR_MASK			BIT(21)

static DEFINE_MUTEX(flow_offload_mutex);
static DEFINE_SPINLOCK(ppe_lock);

static u32 airoha_npu_rr(struct airoha_npu *npu, u32 reg)
{
	return readl(npu->base + reg);
}

static void airoha_npu_wr(struct airoha_npu *npu, u32 reg, u32 val)
{
	writel(val, npu->base + reg);
}

static u32 airoha_npu_rmw(struct airoha_npu *npu, u32 reg, u32 mask, u32 val)
{
	val |= airoha_npu_rr(npu, reg) & ~mask;
	airoha_npu_wr(npu, reg, val);

	return val;
}

static int airoha_npu_send_msg(struct airoha_npu *npu, int func_id,
			       void *p, int size)
{
	int i, ret, timeout = 10000; /* 100ms */
	struct device *dev = &npu->pdev->dev;
	struct npu_mbox_metadata meta = {
		.wait_rsp = 1,
		.func_id = func_id,
	};
	u16 core = 0; /* FIXME */
	u32 val, offset = core << 4;
	dma_addr_t dma_addr;
	void *addr;

	addr = kzalloc(size, GFP_KERNEL | GFP_DMA);
	if (!addr)
		return -ENOMEM;

	memcpy(addr, p, size);
	dma_addr = dma_map_single(dev, addr, size, DMA_TO_DEVICE);
	ret = dma_mapping_error(dev, dma_addr);
	if (ret)
		goto out;

	mutex_lock(&npu->cores[core].mbox_mutex);

	airoha_npu_wr(npu, REG_CR_MBQ0_CTRL(0) + offset, dma_addr);
	airoha_npu_wr(npu, REG_CR_MBQ0_CTRL(1) + offset, size);
	val = airoha_npu_rr(npu, REG_CR_MBQ0_CTRL(2) + offset);
	airoha_npu_wr(npu, REG_CR_MBQ0_CTRL(2) + offset, val + 1);
	airoha_npu_wr(npu, REG_CR_MBQ0_CTRL(3) + offset, meta.data);

	for (i = 0; i < timeout; i++) {
		meta.data = airoha_npu_rr(npu, REG_CR_MBQ0_CTRL(3) + offset);
		if (meta.done) {
			ret = meta.status == NPU_MBOX_SUCCESS ? 0 : -EINVAL;
			break;
		}
		usleep_range(100, 150);
	}

	mutex_unlock(&npu->cores[core].mbox_mutex);

	dma_unmap_single(dev, dma_addr, size, DMA_TO_DEVICE);
out:
	kfree(addr);

	return ret;
}

static int airoha_npu_run_firmware(struct airoha_npu *npu, struct reserved_mem *rmem)
{
	struct device *dev = &npu->pdev->dev;
	const struct firmware *fw;
	void __iomem *addr;
	int ret;

	ret = request_firmware(&fw, NPU_EN7581_FIRMWARE_RV32, dev);
	if (ret)
		return ret;

	if (fw->size > NPU_EN7581_FIRMWARE_RV32_MAX_SIZE) {
		dev_err(dev, "%s: fw size too overlimit (%ld)\n",
			NPU_EN7581_FIRMWARE_RV32, fw->size);
		ret = -E2BIG;
		goto out;
	}

	addr = devm_ioremap(dev, rmem->base, rmem->size);
	if (!addr) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy_toio(addr, fw->data, fw->size);
	release_firmware(fw);

	ret = request_firmware(&fw, NPU_EN7581_FIRMWARE_DATA, dev);
	if (ret)
		return ret;

	if (fw->size > NPU_EN7581_FIRMWARE_DATA_MAX_SIZE) {
		dev_err(dev, "%s: fw size too overlimit (%ld)\n",
			NPU_EN7581_FIRMWARE_DATA, fw->size);
		ret = -E2BIG;
		goto out;
	}

	memcpy_toio(npu->base + REG_NPU_LOCAL_SRAM, fw->data, fw->size);
out:
	release_firmware(fw);

	return ret;
}

static irqreturn_t airoha_npu_mbox_handler(int irq, void *npu_instance)
{
	struct airoha_npu *npu = npu_instance;
	struct npu_mbox_metadata meta;

	/* clear mbox interrupt status */
	airoha_npu_wr(npu, REG_CR_MBOX_INT_STATUS, MBOX_INT_STATUS_MASK);

	/* acknowledge npu */
	meta.data = airoha_npu_rr(npu, REG_CR_MBQ8_CTRL(3));
	meta.status = 0;
	meta.done = 1;
	airoha_npu_wr(npu, REG_CR_MBQ8_CTRL(3), meta.data);

	return IRQ_HANDLED;
}

static int airoha_npu_ppe_init(struct airoha_npu *npu)
{
	struct ppe_mbox_data ppe_data = {
		.func_type = NPU_OP_SET,
		.func_id = PPE_FUNC_SET_WAIT_HWNAT_INIT,
		.init_info = {
			.ppe_type = PPE_TYPE_L2B_IPV4_IPV6,
			.wan_mode = QDMA_WAN_ETHER,
		},
	};

	return airoha_npu_send_msg(npu, NPU_FUNC_PPE, &ppe_data,
				   sizeof(struct ppe_mbox_data));
}

static int airoha_npu_ppe_deinit(struct airoha_npu *npu)
{
	struct ppe_mbox_data ppe_data = {
		.func_type = NPU_OP_SET,
		.func_id = PPE_FUNC_SET_WAIT_HWNAT_DEINIT,
	};

	return airoha_npu_send_msg(npu, NPU_FUNC_PPE, &ppe_data,
				   sizeof(struct ppe_mbox_data));
}

static int airoha_npu_flush_ppe_sram_entries(struct airoha_npu *npu,
					     struct airoha_ppe *ppe)
{
	struct ppe_mbox_data ppe_data = {
		.func_type = NPU_OP_SET,
		.func_id = PPE_FUNC_SET_WAIT_API,
		.set_info = {
			.func_id = PPE_SRAM_RESET_VAL,
			.data = ppe->foe_dma,
			.size = PPE_SRAM_NUM_ENTRIES,
		},
	};

	memset(ppe->foe, 0, PPE_SRAM_NUM_ENTRIES * PPE_EN7581_ENTRY_SIZE);

	return airoha_npu_send_msg(npu, NPU_FUNC_PPE, &ppe_data,
				   sizeof(struct ppe_mbox_data));
}

static void airoha_npu_wdt_work(struct work_struct *work)
{
	struct airoha_npu_core *core;
	struct airoha_npu *npu;
	void *dump;
	int c;

	core = container_of(work, struct airoha_npu_core, wdt_work);
	npu = core->npu;

	dump = vzalloc(NPU_DUMP_SIZE);
	if (!dump)
		return;

	c = core - &npu->cores[0];
	snprintf(dump, NPU_DUMP_SIZE, "PC: %08x SP: %08x LR: %08x\n",
		 airoha_npu_rr(npu, REG_PC_DBG(c)),
		 airoha_npu_rr(npu, REG_PC_DBG(c) + 0x4),
		 airoha_npu_rr(npu, REG_PC_DBG(c) + 0x8));

	dev_coredumpv(&npu->pdev->dev, dump, NPU_DUMP_SIZE, GFP_KERNEL);
}

static irqreturn_t airoha_npu_wdt_handler(int irq, void *core_instance)
{
	struct airoha_npu_core *core = core_instance;
	struct airoha_npu *npu = core->npu;
	int c = core - &npu->cores[0];
	u32 val;

	airoha_npu_rmw(npu, REG_WDT_TIMER_CTRL(c), 0, WDT_INTR_MASK);
	val = airoha_npu_rr(npu, REG_WDT_TIMER_CTRL(c));
	if (FIELD_GET(WDT_EN_MASK, val))
		schedule_work(&core->wdt_work);

	return IRQ_HANDLED;
}

static struct airoha_npu *airoha_npu_init(struct airoha_eth *eth)
{
	struct reserved_mem *rmem;
	int i, irq, err = -ENODEV;
	struct airoha_npu *npu;
	struct device_node *np;

	npu = devm_kzalloc(eth->dev, sizeof(*npu), GFP_KERNEL);
	if(!npu)
		return ERR_PTR(-ENOMEM);

	npu->np = of_parse_phandle(eth->dev->of_node, "airoha,npu", 0);
	if (!npu->np)
		return ERR_PTR(-ENODEV);

	npu->pdev = of_find_device_by_node(npu->np);
	if (!npu->pdev)
		goto error_of_node_put;

	get_device(&npu->pdev->dev);

	npu->base = devm_platform_ioremap_resource(npu->pdev, 0);
	if (IS_ERR(npu->base))
		goto error_put_dev;

	np = of_parse_phandle(npu->np, "memory-region", 0);
	if (!np)
		goto error_put_dev;

	rmem = of_reserved_mem_lookup(np);
	of_node_put(np);

	if (!rmem)
		goto error_put_dev;

	irq = platform_get_irq(npu->pdev, 0);
	if (irq < 0) {
		err = irq;
		goto error_put_dev;
	}

	err = devm_request_irq(&npu->pdev->dev, irq, airoha_npu_mbox_handler,
			       IRQF_SHARED, "airoha-npu-mbox", npu);
	if (err)
		goto error_put_dev;

	for (i = 0; i < ARRAY_SIZE(npu->cores); i++) {
		struct airoha_npu_core *core = &npu->cores[i];

		mutex_init(&core->mbox_mutex);
		core->npu = npu;

		irq = platform_get_irq(npu->pdev, i + 1);
		if (irq < 0) {
			err = irq;
			goto error_put_dev;
		}

		err = devm_request_irq(&npu->pdev->dev, irq,
				       airoha_npu_wdt_handler, IRQF_SHARED,
				       "airoha-npu-wdt", core);
		if (err)
			goto error_put_dev;

		INIT_WORK(&core->wdt_work, airoha_npu_wdt_work);
	}

	if (dma_set_coherent_mask(&npu->pdev->dev, 0xbfffffff))
		dev_err(&npu->pdev->dev,
			"failed coherent DMA configuration\n");

	err = airoha_npu_run_firmware(npu, rmem);
	if (err)
		goto error_put_dev;

	airoha_npu_wr(npu, REG_CR_NPU_MIB(10),
		      rmem->base + NPU_EN7581_FIRMWARE_RV32_MAX_SIZE);
	airoha_npu_wr(npu, REG_CR_NPU_MIB(11), 0x40000); /* SRAM 256K */
	airoha_npu_wr(npu, REG_CR_NPU_MIB(12), 0);
	airoha_npu_wr(npu, REG_CR_NPU_MIB(21), 1);
	msleep(100);

	/* setting booting address */
	for (i = 0; i < AIROHA_NPU_NUM_CORES; i++)
		airoha_npu_wr(npu, REG_CR_BOOT_BASE(i), rmem->base);
	usleep_range(1000, 2000);

	/* enable NPU cores */
	/* do not start core3 since it is used for WiFi offloading */
	airoha_npu_wr(npu, REG_CR_BOOT_CONFIG, 0xf7);
	airoha_npu_wr(npu, REG_CR_BOOT_TRIGGER, 0x1);
	msleep(100);

	return npu;

error_put_dev:
	put_device(&npu->pdev->dev);
error_of_node_put:
	of_node_put(npu->np);

	return ERR_PTR(err);
}

static void airoha_npu_deinit(struct airoha_npu *npu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(npu->cores); i++)
		cancel_work_sync(&npu->cores[i].wdt_work);

	put_device(&npu->pdev->dev);
	of_node_put(npu->np);
}

static const struct rhashtable_params airoha_flow_table_params = {
	.head_offset = offsetof(struct airoha_flow_table_entry, node),
	.key_offset = offsetof(struct airoha_flow_table_entry, cookie),
	.key_len = sizeof(unsigned long),
	.automatic_shrinking = true,
};

static void airoha_ppe_flow_mangle_eth(const struct flow_action_entry *act, void *eth)
{
	void *dest = eth + act->mangle.offset;
	const void *src = &act->mangle.val;

	if (act->mangle.offset > 8)
		return;

	if (act->mangle.mask == 0xffff) {
		src += 2;
		dest += 2;
	}

	memcpy(dest, src, act->mangle.mask ? 2 : 4);
}

static int airoha_ppe_flow_mangle_ports(const struct flow_action_entry *act,
					struct airoha_flow_data *data)
{
	u32 val = be32_to_cpu(act->mangle.val);

	switch (act->mangle.offset) {
	case 0:
		if (act->mangle.mask == ~cpu_to_be32(0xffff))
			data->dst_port = cpu_to_be16(val);
		else
			data->src_port = cpu_to_be16(val >> 16);
		break;
	case 2:
		data->dst_port = cpu_to_be16(val);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int airoha_ppe_flow_mangle_ipv4(const struct flow_action_entry *act,
				       struct airoha_flow_data *data)
{
	__be32 *dest;

	switch (act->mangle.offset) {
	case offsetof(struct iphdr, saddr):
		dest = &data->v4.src_addr;
		break;
	case offsetof(struct iphdr, daddr):
		dest = &data->v4.dst_addr;
		break;
	default:
		return -EINVAL;
	}

	memcpy(dest, &act->mangle.val, sizeof(u32));

	return 0;
}

static int airoha_ppe_flow_set_output_device(struct airoha_foe_entry *hwe,
					     struct net_device *dev,
					     const u8 *dest_mac)
{
	/* FIXME */
	return 0;
}

static int airoha_ppe_foe_entry_prepare(struct airoha_foe_entry *hwe,
					int type, int l4proto, u8 pse_port,
					u8 *src_mac, u8 *dest_mac)
{
	struct airoha_foe_mac_info *l2;
	u32 ports_pad, val;

	memset(hwe, 0, sizeof(*hwe));

	/* FIXME
	if (mtk_is_netsys_v2_or_greater(eth)) {
		val = FIELD_PREP(MTK_FOE_IB1_STATE, MTK_FOE_STATE_BIND) |
		      FIELD_PREP(MTK_FOE_IB1_PACKET_TYPE_V2, type) |
		      FIELD_PREP(MTK_FOE_IB1_UDP, l4proto == IPPROTO_UDP) |
		      MTK_FOE_IB1_BIND_CACHE_V2 | MTK_FOE_IB1_BIND_TTL_V2;
		e->ib1 = val;

		val = FIELD_PREP(MTK_FOE_IB2_DEST_PORT_V2, pse_port) |
		      FIELD_PREP(MTK_FOE_IB2_PORT_AG_V2, 0xf);
	} else {
		int port_mg = eth->soc->offload_version > 1 ? 0 : 0x3f;

		val = FIELD_PREP(MTK_FOE_IB1_STATE, MTK_FOE_STATE_BIND) |
		      FIELD_PREP(MTK_FOE_IB1_PACKET_TYPE, type) |
		      FIELD_PREP(MTK_FOE_IB1_UDP, l4proto == IPPROTO_UDP) |
		      MTK_FOE_IB1_BIND_CACHE | MTK_FOE_IB1_BIND_TTL;
		e->ib1 = val;

		val = FIELD_PREP(MTK_FOE_IB2_DEST_PORT, pse_port) |
		      FIELD_PREP(MTK_FOE_IB2_PORT_MG, port_mg) |
		      FIELD_PREP(MTK_FOE_IB2_PORT_AG, 0x1f);
	}

	if (is_multicast_ether_addr(dest_mac))
		val |= mtk_get_ib2_multicast_mask(eth);

	ports_pad = 0xa5a5a500 | (l4proto & 0xff);
	if (type == MTK_PPE_PKT_TYPE_IPV4_ROUTE)
		e->ipv4.orig.ports = ports_pad;
	if (type == MTK_PPE_PKT_TYPE_IPV6_ROUTE_3T)
		e->ipv6.ports = ports_pad;
*/

	if (type >= AIROHA_PPE_PKT_TYPE_IPV4_DSLITE) {
		hwe->ipv6.ib2 = val;
		l2 = &hwe->ipv6.l2;
	} else {
		hwe->ipv4.ib2 = val;
		l2 = &hwe->ipv4.l2;
	}

	l2->dest_mac_hi = get_unaligned_be32(dest_mac);
	l2->dest_mac_lo = get_unaligned_be16(dest_mac + 4);
	l2->src_mac_hi = get_unaligned_be32(src_mac);
	l2->src_mac_lo = get_unaligned_be16(src_mac + 4);

	if (type >= AIROHA_PPE_PKT_TYPE_IPV6_ROUTE_3T)
		l2->etype = ETH_P_IPV6;
	else
		l2->etype = ETH_P_IP;

	return 0;
}

static int airoha_ppe_foe_entry_set_ipv4_tuple(struct airoha_foe_entry *hwe,
					       struct airoha_flow_data *data,
					       bool egress)
{
	int type = FIELD_GET(AIROHA_FOE_IB1_PACKET_TYPE, hwe->ib1);
	struct airoha_ipv4_tuple *t;

	switch (type) {
	case AIROHA_PPE_PKT_TYPE_IPV4_HNAPT:
		if (egress) {
			t = &hwe->ipv4.new_tuple;
			break;
		}
		fallthrough;
	case AIROHA_PPE_PKT_TYPE_IPV4_DSLITE:
	case AIROHA_PPE_PKT_TYPE_IPV4_ROUTE:
		t = &hwe->ipv4.orig_tuple;
		break;
	case AIROHA_PPE_PKT_TYPE_IPV6_6RD:
		hwe->ipv6_6rd.tunnel_src_ip = be32_to_cpu(data->v4.src_addr);
		hwe->ipv6_6rd.tunnel_dest_ip = be32_to_cpu(data->v4.dst_addr);
		return 0;
	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	t->src_ip = be32_to_cpu(data->v4.src_addr);
	t->dest_ip = be32_to_cpu(data->v4.dst_addr);

	if (type != AIROHA_PPE_PKT_TYPE_IPV4_ROUTE) {
		t->src_port = be16_to_cpu(data->src_port);
		t->dest_port = be16_to_cpu(data->dst_port);
	}

	return 0;
}

static int airoha_ppe_foe_entry_set_ipv6_tuple(struct airoha_foe_entry *hwe,
					       struct airoha_flow_data *data)

{
	int type = FIELD_GET(AIROHA_FOE_IB1_PACKET_TYPE, hwe->ib1);
	u32 *src, *dest;

	switch (type) {
	case AIROHA_PPE_PKT_TYPE_IPV4_DSLITE:
		src = hwe->dslite.tunnel_src_ip;
		dest = hwe->dslite.tunnel_dest_ip;
		break;
	case AIROHA_PPE_PKT_TYPE_IPV6_ROUTE_5T:
	case AIROHA_PPE_PKT_TYPE_IPV6_6RD:
		hwe->ipv6.src_port = be16_to_cpu(data->src_port);
		hwe->ipv6.dest_port = be16_to_cpu(data->dst_port);
		fallthrough;
	case AIROHA_PPE_PKT_TYPE_IPV6_ROUTE_3T:
		src = hwe->ipv6.src_ip;
		dest = hwe->ipv6.dest_ip;
		break;
	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	ipv6_addr_be32_to_cpu(src, data->v6.src_addr.s6_addr32);
	ipv6_addr_be32_to_cpu(dest, data->v6.dst_addr.s6_addr32);

	return 0;
}

static u32 airoha_ppe_foe_get_entry_hash(struct airoha_foe_entry *hwe)
{
	int type = FIELD_GET(AIROHA_FOE_IB1_PACKET_TYPE, hwe->ib1);
	u32 hash, hv1, hv2, hv3;

	switch (type) {
		case AIROHA_PPE_PKT_TYPE_IPV4_ROUTE:
		case AIROHA_PPE_PKT_TYPE_IPV4_HNAPT:
			hv1 = hwe->ipv4.orig_tuple.ports;
			hv2 = hwe->ipv4.orig_tuple.dest_ip;
			hv3 = hwe->ipv4.orig_tuple.src_ip;
			break;
		case AIROHA_PPE_PKT_TYPE_IPV6_ROUTE_3T:
		case AIROHA_PPE_PKT_TYPE_IPV6_ROUTE_5T:
			hv1 = hwe->ipv6.src_ip[3] ^ hwe->ipv6.dest_ip[3];
			hv1 ^= hwe->ipv6.ports;

			hv2 = hwe->ipv6.src_ip[2] ^ hwe->ipv6.dest_ip[2];
			hv2 ^= hwe->ipv6.dest_ip[0];

			hv3 = hwe->ipv6.src_ip[1] ^ hwe->ipv6.dest_ip[1];
			hv3 ^= hwe->ipv6.src_ip[0];
			break;
		case AIROHA_PPE_PKT_TYPE_IPV4_DSLITE:
		case AIROHA_PPE_PKT_TYPE_IPV6_6RD:
		default:
			WARN_ON_ONCE(1);
			return PPE_HASH_MASK;
	}

	hash = (hv1 & hv2) | ((~hv1) & hv3);
	hash = (hash >> 24) | ((hash & 0xffffff) << 8);
	hash ^= hv1 ^ hv2 ^ hv3;
	hash ^= hash >> 16;
	hash <<= __ffs(PPE_EN7581_HASH_OFFSET);
	hash &= PPE_NUM_ENTRIES - 1;

	return hash;
}

static int airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe,
				       struct airoha_flow_table_entry *e,
				       u32 hash)
{
	/* FIXME */
	return 0;
}

static struct airoha_foe_entry *airoha_ppe_foe_get_entry(struct airoha_ppe *ppe,
							 u32 hash)
{
	if (hash < PPE_SRAM_NUM_ENTRIES) {
		u32 *hwe = ppe->foe + hash * PPE_EN7581_ENTRY_SIZE;
		struct airoha_eth *eth = ppe->eth;
		u32 val;
		int i;

		airoha_fe_wr(ppe->eth, REG_PPE1_RAM_CTRL,
			     FIELD_PREP(PPE1_SRAM_CTRL_ENTRY_MASK, hash) |
			     PPE1_SRAM_CTRL_REQ_MASK);
		if (read_poll_timeout_atomic(airoha_fe_rr, val,
					     val & PPE1_SRAM_CTRL_ACK_MASK,
					     10, 100, false, eth,
					     REG_PPE1_RAM_CTRL))
			return NULL;

		for (i = 0; i < PPE_EN7581_ENTRY_SIZE / 4; i++)
			hwe[i] = airoha_fe_rr(eth, REG_PPE1_RAM_ENTRY(i));
	}

	return ppe->foe + hash * PPE_EN7581_ENTRY_SIZE;
}

static bool airoha_ppe_foe_compare_entry(struct airoha_flow_table_entry *e,
					 struct airoha_foe_entry *hwe)
{
	int type = FIELD_GET(AIROHA_FOE_IB1_PACKET_TYPE, e->data.ib1), len;

	if ((hwe->ib1 ^ e->data.ib1) & AIROHA_FOE_IB1_UDP)
		return false;

	if (type > AIROHA_PPE_PKT_TYPE_IPV4_DSLITE)
		len = offsetof(struct airoha_foe_entry, ipv6.rsv);
	else
		len = offsetof(struct airoha_foe_entry, ipv4.ib2);

	return !memcmp(&e->data.data, &hwe->data, len - 4);
}

static void airoha_ppe_foe_insert_entry(struct airoha_ppe *ppe, u32 hash)
{
	struct airoha_flow_table_entry *e;
	struct airoha_foe_entry *hwe;
	struct hlist_node *n;

	spin_lock_bh(&ppe_lock);

	hwe = airoha_ppe_foe_get_entry(ppe, hash);
	if (!hwe)
		goto unlock;

	if (FIELD_GET(AIROHA_FOE_IB1_STATE, hwe->ib1) == AIROHA_FOE_STATE_BIND)
		goto unlock;

	hlist_for_each_entry_safe(e, n,
				  &ppe->foe_flow[hash / PPE_EN7581_HASH_OFFSET],
				  list) {
		if (airoha_ppe_foe_compare_entry(e, hwe)) {
			airoha_ppe_foe_commit_entry(ppe, e, hash);
			e->hash = hash;
			break;
		}
	}
unlock:
	spin_unlock_bh(&ppe_lock);
}

static void airoha_ppe_foe_remove_entry(struct airoha_ppe *ppe,
					struct airoha_flow_table_entry *e)
{
	if (e->hash == 0xffff)
		return;

	/* FIXME */
}

static int airoha_ppe_foe_flow_commit_entry(struct airoha_ppe *ppe,
					    struct airoha_flow_table_entry *e)
{
	u32 hash = airoha_ppe_foe_get_entry_hash(&e->data);

	e->hash = 0xffff;

	spin_lock_bh(&ppe_lock);
	hlist_add_head(&e->list, &ppe->foe_flow[hash / PPE_EN7581_HASH_OFFSET]);
	spin_unlock_bh(&ppe_lock);

	return 0;
}

static void airoha_ppe_foe_flow_remove_entry(struct airoha_ppe *ppe,
					     struct airoha_flow_table_entry *e)
{
	spin_lock_bh(&ppe_lock);

	hlist_del_init(&e->list);
	airoha_ppe_foe_remove_entry(ppe, e);
	e->hash = 0xffff;

	spin_unlock_bh(&ppe_lock);
}

static int airoha_ppe_flow_offload_replace(struct airoha_gdm_port *port,
					   struct flow_cls_offload *f)
{
	struct flow_rule *rule = flow_cls_offload_flow_rule(f);
	struct airoha_eth *eth = port->qdma->eth;
	struct airoha_flow_table_entry *e;
	struct airoha_flow_data data = {};
	struct net_device *odev = NULL;
	struct flow_action_entry *act;
	struct airoha_foe_entry hwe;
	int err, i, offload_type;
	u16 addr_type = 0;
	u8 l4proto = 0;

	if (rhashtable_lookup(&eth->flow_table, &f->cookie, airoha_flow_table_params))
		return -EEXIST;

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return -EOPNOTSUPP;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(rule, &match);
		addr_type = match.key->addr_type;
		if (flow_rule_has_control_flags(match.mask->flags,
						f->common.extack))
			return -EOPNOTSUPP;
	} else {
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);
		l4proto = match.key->ip_proto;
	} else {
		return -EOPNOTSUPP;
	}

	switch (addr_type) {
	case FLOW_DISSECTOR_KEY_IPV4_ADDRS:
		offload_type = AIROHA_PPE_PKT_TYPE_IPV4_HNAPT;
		break;
	case FLOW_DISSECTOR_KEY_IPV6_ADDRS:
		offload_type = AIROHA_PPE_PKT_TYPE_IPV6_ROUTE_5T;
		break;
	default:
		return -EOPNOTSUPP;
	}

	flow_action_for_each(i, act, &rule->action) {
		switch (act->id) {
		case FLOW_ACTION_MANGLE:
			if (offload_type == AIROHA_PPE_PKT_TYPE_BRIDGE)
				return -EOPNOTSUPP;

			if (act->mangle.htype == FLOW_ACT_MANGLE_HDR_TYPE_ETH)
				airoha_ppe_flow_mangle_eth(act, &data.eth);
			break;
		case FLOW_ACTION_REDIRECT:
			odev = act->dev;
			break;
		case FLOW_ACTION_CSUM:
			break;
		case FLOW_ACTION_VLAN_PUSH:
			if (data.vlan.num == 1 ||
			    act->vlan.proto != htons(ETH_P_8021Q))
				return -EOPNOTSUPP;

			data.vlan.id = act->vlan.vid;
			data.vlan.proto = act->vlan.proto;
			data.vlan.num++;
			break;
		case FLOW_ACTION_VLAN_POP:
			break;
		case FLOW_ACTION_PPPOE_PUSH:
			if (data.pppoe.num == 1)
				return -EOPNOTSUPP;

			data.pppoe.sid = act->pppoe.sid;
			data.pppoe.num++;
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	if (!is_valid_ether_addr(data.eth.h_source) ||
	    !is_valid_ether_addr(data.eth.h_dest))
		return -EINVAL;

	err = airoha_ppe_foe_entry_prepare(&hwe, offload_type, l4proto, 0,
					   data.eth.h_source, data.eth.h_dest);
	if (err)
		return err;

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports ports;

		if (offload_type == AIROHA_PPE_PKT_TYPE_BRIDGE)
			return -EOPNOTSUPP;

		flow_rule_match_ports(rule, &ports);
		data.src_port = ports.key->src;
		data.dst_port = ports.key->dst;
	} else if (offload_type != AIROHA_PPE_PKT_TYPE_BRIDGE) {
		return -EOPNOTSUPP;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs addrs;

		flow_rule_match_ipv4_addrs(rule, &addrs);
		data.v4.src_addr = addrs.key->src;
		data.v4.dst_addr = addrs.key->dst;
		airoha_ppe_foe_entry_set_ipv4_tuple(&hwe, &data, false);
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_match_ipv6_addrs addrs;

		flow_rule_match_ipv6_addrs(rule, &addrs);

		data.v6.src_addr = addrs.key->src;
		data.v6.dst_addr = addrs.key->dst;
		airoha_ppe_foe_entry_set_ipv6_tuple(&hwe, &data);
	}

	flow_action_for_each(i, act, &rule->action) {
		if (act->id != FLOW_ACTION_MANGLE)
			continue;

		if (offload_type == AIROHA_PPE_PKT_TYPE_BRIDGE)
			return -EOPNOTSUPP;

		switch (act->mangle.htype) {
		case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
		case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
			err = airoha_ppe_flow_mangle_ports(act, &data);
			break;
		case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
			err = airoha_ppe_flow_mangle_ipv4(act, &data);
			break;
		case FLOW_ACT_MANGLE_HDR_TYPE_ETH:
			/* handled earlier */
			break;
		default:
			return -EOPNOTSUPP;
		}

		if (err)
			return err;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		err = airoha_ppe_foe_entry_set_ipv4_tuple(&hwe, &data, true);
		if (err)
			return err;
	}

	err = airoha_ppe_flow_set_output_device(&hwe, odev, data.eth.h_dest);
	if (err)
		return err;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->cookie = f->cookie;
	memcpy(&e->data, &hwe, sizeof(e->data));

	err = airoha_ppe_foe_flow_commit_entry(eth->ppe, e);
	if (err)
		goto free_entry;

	err = rhashtable_insert_fast(&eth->flow_table, &e->node,
				     airoha_flow_table_params);
	if (err < 0)
		goto remove_foe_entry;

	return 0;

remove_foe_entry:
	airoha_ppe_foe_flow_remove_entry(eth->ppe, e);
free_entry:
	kfree(e);

	return err;
}

static int airoha_ppe_flow_offload_destroy(struct airoha_gdm_port *port,
					   struct flow_cls_offload *f)
{
	struct airoha_eth *eth = port->qdma->eth;
	struct airoha_flow_table_entry *e;

	e = rhashtable_lookup(&eth->flow_table, &f->cookie,
			      airoha_flow_table_params);
	if (!e)
		return -ENOENT;

	airoha_ppe_foe_flow_remove_entry(eth->ppe, e);
	rhashtable_remove_fast(&eth->flow_table, &e->node,
			       airoha_flow_table_params);
	kfree(e);

	return 0;
}

static int airoha_ppe_flow_offload_cmd(struct airoha_gdm_port *port,
				       struct flow_cls_offload *f)
{
	int err = -EOPNOTSUPP;

	mutex_lock(&flow_offload_mutex);

	switch (f->command) {
	case FLOW_CLS_REPLACE:
		err = airoha_ppe_flow_offload_replace(port, f);
		break;
	case FLOW_CLS_DESTROY:
		err = airoha_ppe_flow_offload_destroy(port, f);
		break;
	default:
		break;
	}

	mutex_unlock(&flow_offload_mutex);

	return err;
}

int airoha_ppe_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
				 void *cb_priv)
{
	struct flow_cls_offload *cls = type_data;
	struct net_device *dev = cb_priv;
	struct airoha_gdm_port *port = netdev_priv(dev);

	if (!tc_can_offload(dev) || type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	return airoha_ppe_flow_offload_cmd(port, cls);
}

void airoha_ppe_check_skb(struct airoha_ppe *ppe, struct sk_buff *skb, u16 hash)
{
	u16 now, diff;

	if (hash > PPE_HASH_MASK)
		return;

	now = (u16)jiffies;
	diff = now - ppe->foe_check_time[hash];
	if (diff < HZ / 10)
		return;

	ppe->foe_check_time[hash] = now;
	airoha_ppe_foe_insert_entry(ppe, hash);
}

int airoha_ppe_init(struct airoha_eth *eth)
{
	struct airoha_npu *npu;
	struct airoha_ppe *ppe;
	u32 foe_flow_size;
	int err;

	ppe = devm_kzalloc(eth->dev, sizeof(*ppe), GFP_KERNEL);
	if (!ppe)
		return -ENOMEM;

	ppe->foe = dmam_alloc_coherent(eth->dev,
				       PPE_NUM_ENTRIES * PPE_EN7581_ENTRY_SIZE,
				       &ppe->foe_dma, GFP_KERNEL);
	if (!ppe->foe)
		return -ENOMEM;

	memset(ppe->foe, 0, PPE_NUM_ENTRIES * PPE_EN7581_ENTRY_SIZE);
	ppe->eth = eth;

	airoha_fe_wr(eth, REG_PPE1_TB_BASE,
		     ppe->foe_dma + PPE_EN7581_DRAM_OFFSET);
	airoha_fe_wr(eth, REG_PPE2_TB_BASE,
		     ppe->foe_dma + PPE_EN7581_DRAM_OFFSET);
	airoha_fe_rmw(eth, REG_PPE1_BND_AGE0,
		      PPE1_BIND_AGE0_DELTA_NON_L4 |
		      PPE1_BIND_AGE0_DELTA_UDP,
		      FIELD_PREP(PPE1_BIND_AGE0_DELTA_NON_L4, 1) |
		      FIELD_PREP(PPE1_BIND_AGE0_DELTA_UDP, 12));
	airoha_fe_rmw(eth, REG_PPE1_BND_AGE1,
		      PPE1_BIND_AGE1_DELTA_TCP_FIN |
		      PPE1_BIND_AGE1_DELTA_TCP,
		      FIELD_PREP(PPE1_BIND_AGE1_DELTA_TCP_FIN, 1) |
		      FIELD_PREP(PPE1_BIND_AGE1_DELTA_TCP, 7));
	eth->ppe = ppe;

	foe_flow_size = (PPE_NUM_ENTRIES / PPE_EN7581_HASH_OFFSET) *
			sizeof(*ppe->foe_flow);
	ppe->foe_flow = devm_kzalloc(eth->dev, foe_flow_size, GFP_KERNEL);
	if (!ppe->foe_flow)
		return -ENOMEM;

	err = rhashtable_init(&eth->flow_table, &airoha_flow_table_params);
	if (err)
		return err;

	npu = airoha_npu_init(eth);
	if (IS_ERR(npu)) {
		err = PTR_ERR(npu);
		goto error_destroy_flow_table;
	}

	eth->npu = npu;
	err = airoha_npu_ppe_init(npu);
	if (err)
		goto error_npu_deinit;

	err = airoha_npu_flush_ppe_sram_entries(npu, ppe);
	if (err)
		goto error_npu_deinit;

	return 0;

error_npu_deinit:
	airoha_npu_deinit(npu);
	eth->npu = NULL;
error_destroy_flow_table:
	rhashtable_destroy(&eth->flow_table);

	return err;
}

void airoha_ppe_deinit(struct airoha_eth *eth)
{
	if (eth->npu) {
		airoha_npu_ppe_deinit(eth->npu);
		airoha_npu_deinit(eth->npu);
	}
	rhashtable_destroy(&eth->flow_table);
}
