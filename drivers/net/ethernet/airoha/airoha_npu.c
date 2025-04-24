// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 AIROHA Inc
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/devcoredump.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <linux/of_net.h>
#include <linux/of_platform.h>
#include <linux/of_reserved_mem.h>
#include <linux/regmap.h>
#include <linux/soc/airoha/airoha_npu.h>
#include <net/page_pool/helpers.h>

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

#define NPU_WLAN_BASE_ADDR		0x30d000

#define REG_IRQ_STATUS			(NPU_WLAN_BASE_ADDR + 0x030)
#define REG_IRQ_RXDONE(_n)		(NPU_WLAN_BASE_ADDR + ((_n) << 2) + 0x034)
#define NPU_IRQ_RX_MASK(_n)		((_n) == 1 ? BIT(17) : BIT(16))

#define REG_TX_BASE(_n)			(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x080)
#define REG_TX_DSCP_NUM(_n)		(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x084)
#define REG_TX_DMA_IDX(_n)		(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x088)
#define REG_TX_CPU_IDX(_n)		(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x08c)

#define REG_RX_BASE(_n)			(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x180)
#define REG_RX_DSCP_NUM(_n)		(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x184)
#define REG_RX_DMA_IDX(_n)		(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x188)
#define REG_RX_CPU_IDX(_n)		(NPU_WLAN_BASE_ADDR + ((_n) << 4) + 0x18c)

#define NPU_TIMER_BASE_ADDR		0x310100
#define REG_WDT_TIMER_CTRL(_n)		(NPU_TIMER_BASE_ADDR + ((_n) * 0x100))
#define WDT_EN_MASK			BIT(25)
#define WDT_INTR_MASK			BIT(21)

enum {
	NPU_OP_SET = 1,
	NPU_OP_SET_NO_WAIT,
	NPU_OP_GET,
	NPU_OP_GET_NO_WAIT,
};

enum {
	NPU_FUNC_WIFI,
	NPU_FUNC_TUNNEL,
	NPU_FUNC_NOTIFY,
	NPU_FUNC_DBA,
	NPU_FUNC_TR471,
	NPU_FUNC_PPE,
};

enum {
	NPU_MBOX_ERROR,
	NPU_MBOX_SUCCESS,
};

enum {
	PPE_FUNC_SET_WAIT,
	PPE_FUNC_SET_WAIT_HWNAT_INIT,
	PPE_FUNC_SET_WAIT_HWNAT_DEINIT,
	PPE_FUNC_SET_WAIT_API,
};

enum {
	PPE2_SRAM_SET_ENTRY,
	PPE_SRAM_SET_ENTRY,
	PPE_SRAM_SET_VAL,
	PPE_SRAM_RESET_VAL,
};

enum {
	QDMA_WAN_ETHER = 1,
	QDMA_WAN_PON_XDSL,
};

#define MBOX_MSG_FUNC_ID	GENMASK(14, 11)
#define MBOX_MSG_STATIC_BUF	BIT(5)
#define MBOX_MSG_STATUS		GENMASK(4, 2)
#define MBOX_MSG_DONE		BIT(1)
#define MBOX_MSG_WAIT_RSP	BIT(0)

#define PPE_TYPE_L2B_IPV4	2
#define PPE_TYPE_L2B_IPV4_IPV6	3

struct ppe_mbox_data {
	u32 func_type;
	u32 func_id;
	union {
		struct {
			u8 cds;
			u8 xpon_hal_api;
			u8 wan_xsi;
			u8 ct_joyme4;
			int ppe_type;
			int wan_mode;
			int wan_sel;
		} init_info;
		struct {
			int func_id;
			u32 size;
			u32 data;
		} set_info;
	};
};

enum {
	WLAN_FUNC_SET_WAIT_PCIE_ADDR,
	WLAN_FUNC_SET_WAIT_DESC,
	WLAN_FUNC_SET_WAIT_NPU_INIT_DONE,
	WLAN_FUNC_SET_WAIT_TRAN_TO_CPU,
	WLAN_FUNC_SET_WAIT_BA_WIN_SIZE,
	WLAN_FUNC_SET_WAIT_DRIVER_MODEL,
	WLAN_FUNC_SET_WAIT_DEL_STA,
	WLAN_FUNC_SET_WAIT_DRAM_BA_NODE_ADDR,
	WLAN_FUNC_SET_WAIT_PKT_BUF_ADDR,
	WLAN_FUNC_SET_WAIT_IS_TEST_NOBA,
	WLAN_FUNC_SET_WAIT_FLUSHONE_TIMEOUT,
	WLAN_FUNC_SET_WAIT_FLUSHALL_TIMEOUT,
	WLAN_FUNC_SET_WAIT_IS_FORCE_TO_CPU,
	WLAN_FUNC_SET_WAIT_PCIE_STATE,
	WLAN_FUNC_SET_WAIT_PCIE_PORT_TYPE,
	WLAN_FUNC_SET_WAIT_ERROR_RETRY_TIMES,
	WLAN_FUNC_SET_WAIT_BAR_INFO,
	WLAN_FUNC_SET_WAIT_FAST_FLAG,
	WLAN_FUNC_SET_WAIT_NPU_BAND0_ONCPU,
	WLAN_FUNC_SET_WAIT_TX_RING_PCIE_ADDR,
	WLAN_FUNC_SET_WAIT_TX_DESC_HW_BASE,
	WLAN_FUNC_SET_WAIT_TX_BUF_SPACE_HW_BASE,
	WLAN_FUNC_SET_WAIT_RX_RING_FOR_TXDONE_HW_BASE,
	WLAN_FUNC_SET_WAIT_TX_PKT_BUF_ADDR,
	WLAN_FUNC_SET_WAIT_INODE_TXRX_REG_ADDR,
	WLAN_FUNC_SET_WAIT_INODE_DEBUG_FLAG,
	WLAN_FUNC_SET_WAIT_INODE_HW_CFG_INFO,
	WLAN_FUNC_SET_WAIT_INODE_STOP_ACTION,
	WLAN_FUNC_SET_WAIT_INODE_PCIE_SWAP,
	WLAN_FUNC_SET_WAIT_RATELIMIT_CTRL,
	WLAN_FUNC_SET_WAIT_HWNAT_INIT,
	WLAN_FUNC_SET_WAIT_ARHT_CHIP_INFO,
	WLAN_FUNC_SET_WAIT_TX_BUF_CHECK_ADDR,
	WLAN_FUNC_SET_WAIT_DEBUG_ARRAY_ADDR,
};

enum {
	WLAN_FUNC_GET_WAIT_NPU_INFO,
	WLAN_FUNC_GET_WAIT_LAST_RATE,
	WLAN_FUNC_GET_WAIT_COUNTER,
	WLAN_FUNC_GET_WAIT_DBG_COUNTER,
	WLAN_FUNC_GET_WAIT_RXDESC_BASE,
	WLAN_FUNC_GET_WAIT_WCID_DBG_COUNTER,
	WLAN_FUNC_GET_WAIT_DMA_ADDR,
	WLAN_FUNC_GET_WAIT_RING_SIZE,
	WLAN_FUNC_GET_WAIT_NPU_SUPPORT_MAP,
	WLAN_FUNC_GET_WAIT_MDC_LOCK_ADDRESS,
};

#define WLAN_MAX_SSID	8
#define WLAN_MAX_ENTRY	128

struct wlan_mbox_data {
	u32 ifindex:4;
	u32 func_type:4;
	u32 func_id;
	union {
		u32 data;
		struct {
			u32 dir;
			u32 in_counter_addr;
			u32 out_status_addr;
			u32 out_counter_addr;
		} txrx_addr;
		struct {
			u32 tx_pkts;
			u64 rx_pkts_2g[WLAN_MAX_SSID];
			u64 rx_pkts_5g[WLAN_MAX_SSID];
			u64 rx_bytes_2g[WLAN_MAX_SSID];
			u64 rx_bytes_5g[WLAN_MAX_SSID];
			u8 omac_idx_5g[WLAN_MAX_SSID];
			u8 omac_idx_2g[WLAN_MAX_SSID];
			u64 rx_ap_cli_pkts_2g;
			u64 rx_ap_cli_pkts_5g;
			u64 rx_ap_cli_bytes_2g;
			u64 rx_ap_cli_bytes_5g;
			u64 rx_pkts_entry[2][WLAN_MAX_ENTRY];
			u64 rx_bytes_entry[2][WLAN_MAX_ENTRY];
		} stats;
	};
};

struct npu_tx_dma_desc {
	u32 ctrl;
	u32 addr;
	u64 rsv;
	u8 data[192];
} __packed;

static int airoha_npu_send_msg(struct airoha_npu *npu, int func_id,
			       void *p, int size)
{
	u16 core = 0; /* FIXME */
	u32 val, offset = core << 4;
	dma_addr_t dma_addr;
	int ret;

	dma_addr = dma_map_single(npu->dev, p, size, DMA_TO_DEVICE);
	ret = dma_mapping_error(npu->dev, dma_addr);
	if (ret)
		return ret;

	spin_lock_bh(&npu->cores[core].lock);

	regmap_write(npu->regmap, REG_CR_MBQ0_CTRL(0) + offset, dma_addr);
	regmap_write(npu->regmap, REG_CR_MBQ0_CTRL(1) + offset, size);
	regmap_read(npu->regmap, REG_CR_MBQ0_CTRL(2) + offset, &val);
	regmap_write(npu->regmap, REG_CR_MBQ0_CTRL(2) + offset, val + 1);
	val = FIELD_PREP(MBOX_MSG_FUNC_ID, func_id) | MBOX_MSG_WAIT_RSP;
	regmap_write(npu->regmap, REG_CR_MBQ0_CTRL(3) + offset, val);

	ret = regmap_read_poll_timeout_atomic(npu->regmap,
					      REG_CR_MBQ0_CTRL(3) + offset,
					      val, (val & MBOX_MSG_DONE),
					      100, 100 * MSEC_PER_SEC);
	if (!ret && FIELD_GET(MBOX_MSG_STATUS, val) != NPU_MBOX_SUCCESS)
		ret = -EINVAL;

	spin_unlock_bh(&npu->cores[core].lock);

	dma_unmap_single(npu->dev, dma_addr, size, DMA_TO_DEVICE);

	return ret;
}

static int airoha_npu_run_firmware(struct device *dev, void __iomem *base,
				   struct reserved_mem *rmem)
{
	const struct firmware *fw;
	void __iomem *addr;
	int ret;

	ret = request_firmware(&fw, NPU_EN7581_FIRMWARE_RV32, dev);
	if (ret)
		return ret == -ENOENT ? -EPROBE_DEFER : ret;

	if (fw->size > NPU_EN7581_FIRMWARE_RV32_MAX_SIZE) {
		dev_err(dev, "%s: fw size too overlimit (%zu)\n",
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
		return ret == -ENOENT ? -EPROBE_DEFER : ret;

	if (fw->size > NPU_EN7581_FIRMWARE_DATA_MAX_SIZE) {
		dev_err(dev, "%s: fw size too overlimit (%zu)\n",
			NPU_EN7581_FIRMWARE_DATA, fw->size);
		ret = -E2BIG;
		goto out;
	}

	memcpy_toio(base + REG_NPU_LOCAL_SRAM, fw->data, fw->size);
out:
	release_firmware(fw);

	return ret;
}

static irqreturn_t airoha_npu_mbox_handler(int irq, void *npu_instance)
{
	struct airoha_npu *npu = npu_instance;

	/* clear mbox interrupt status */
	regmap_write(npu->regmap, REG_CR_MBOX_INT_STATUS,
		     MBOX_INT_STATUS_MASK);

	/* acknowledge npu */
	regmap_update_bits(npu->regmap, REG_CR_MBQ8_CTRL(3),
			   MBOX_MSG_STATUS | MBOX_MSG_DONE, MBOX_MSG_DONE);

	return IRQ_HANDLED;
}

static void airoha_npu_wdt_work(struct work_struct *work)
{
	struct airoha_npu_core *core;
	struct airoha_npu *npu;
	void *dump;
	u32 val[3];
	int c;

	core = container_of(work, struct airoha_npu_core, wdt_work);
	npu = core->npu;

	dump = vzalloc(NPU_DUMP_SIZE);
	if (!dump)
		return;

	c = core - &npu->cores[0];
	regmap_bulk_read(npu->regmap, REG_PC_DBG(c), val, ARRAY_SIZE(val));
	snprintf(dump, NPU_DUMP_SIZE, "PC: %08x SP: %08x LR: %08x\n",
		 val[0], val[1], val[2]);

	dev_coredumpv(npu->dev, dump, NPU_DUMP_SIZE, GFP_KERNEL);
}

static irqreturn_t airoha_npu_wdt_handler(int irq, void *core_instance)
{
	struct airoha_npu_core *core = core_instance;
	struct airoha_npu *npu = core->npu;
	int c = core - &npu->cores[0];
	u32 val;

	regmap_set_bits(npu->regmap, REG_WDT_TIMER_CTRL(c), WDT_INTR_MASK);
	if (!regmap_read(npu->regmap, REG_WDT_TIMER_CTRL(c), &val) &&
	    FIELD_GET(WDT_EN_MASK, val))
		schedule_work(&core->wdt_work);

	return IRQ_HANDLED;
}

static int airoha_npu_ppe_init(struct airoha_npu *npu)
{
	struct ppe_mbox_data *ppe_data;
	int err;

	ppe_data = kzalloc(sizeof(*ppe_data), GFP_KERNEL);
	if (!ppe_data)
		return -ENOMEM;

	ppe_data->func_type = NPU_OP_SET;
	ppe_data->func_id = PPE_FUNC_SET_WAIT_HWNAT_INIT;
	ppe_data->init_info.ppe_type = PPE_TYPE_L2B_IPV4_IPV6;
	ppe_data->init_info.wan_mode = QDMA_WAN_ETHER;

	err = airoha_npu_send_msg(npu, NPU_FUNC_PPE, ppe_data,
				  sizeof(*ppe_data));
	kfree(ppe_data);

	return err;
}

static int airoha_npu_ppe_deinit(struct airoha_npu *npu)
{
	struct ppe_mbox_data *ppe_data;
	int err;

	ppe_data = kzalloc(sizeof(*ppe_data), GFP_KERNEL);
	if (!ppe_data)
		return -ENOMEM;

	ppe_data->func_type = NPU_OP_SET;
	ppe_data->func_id = PPE_FUNC_SET_WAIT_HWNAT_DEINIT;

	err = airoha_npu_send_msg(npu, NPU_FUNC_PPE, ppe_data,
				  sizeof(*ppe_data));
	kfree(ppe_data);

	return err;
}

static int airoha_npu_ppe_flush_sram_entries(struct airoha_npu *npu,
					     dma_addr_t foe_addr,
					     int sram_num_entries)
{
	struct ppe_mbox_data *ppe_data;
	int err;

	ppe_data = kzalloc(sizeof(*ppe_data), GFP_KERNEL);
	if (!ppe_data)
		return -ENOMEM;

	ppe_data->func_type = NPU_OP_SET;
	ppe_data->func_id = PPE_FUNC_SET_WAIT_API;
	ppe_data->set_info.func_id = PPE_SRAM_RESET_VAL;
	ppe_data->set_info.data = foe_addr;
	ppe_data->set_info.size = sram_num_entries;

	err = airoha_npu_send_msg(npu, NPU_FUNC_PPE, ppe_data,
				  sizeof(*ppe_data));
	kfree(ppe_data);

	return err;
}

static int airoha_npu_foe_commit_entry(struct airoha_npu *npu,
				       dma_addr_t foe_addr,
				       u32 entry_size, u32 hash, bool ppe2)
{
	struct ppe_mbox_data *ppe_data;
	int err;

	ppe_data = kzalloc(sizeof(*ppe_data), GFP_ATOMIC);
	if (!ppe_data)
		return -ENOMEM;

	ppe_data->func_type = NPU_OP_SET;
	ppe_data->func_id = PPE_FUNC_SET_WAIT_API;
	ppe_data->set_info.data = foe_addr;
	ppe_data->set_info.size = entry_size;
	ppe_data->set_info.func_id = ppe2 ? PPE2_SRAM_SET_ENTRY
					  : PPE_SRAM_SET_ENTRY;

	err = airoha_npu_send_msg(npu, NPU_FUNC_PPE, ppe_data,
				  sizeof(*ppe_data));
	if (err)
		return err;

	ppe_data->set_info.func_id = PPE_SRAM_SET_VAL;
	ppe_data->set_info.data = hash;
	ppe_data->set_info.size = sizeof(u32);

	err = airoha_npu_send_msg(npu, NPU_FUNC_PPE, ppe_data,
				  sizeof(*ppe_data));
	kfree(ppe_data);

	return err;
}

static int airoha_npu_wlan_send_msg(struct airoha_npu *npu, int index,
				    int func_id, u32 data)
{
	struct wlan_mbox_data *wlan_data;
	int err;

	wlan_data = kzalloc(sizeof(*wlan_data), GFP_KERNEL);
	if (!wlan_data)
		return -ENOMEM;

	wlan_data->ifindex = index;
	wlan_data->func_type = NPU_OP_SET;
	wlan_data->func_id = func_id;
	wlan_data->data = data;

	err = airoha_npu_send_msg(npu, NPU_FUNC_WIFI, wlan_data,
				  sizeof(*wlan_data));
	kfree(wlan_data);

	return err;
}

static int airoha_npu_wlan_get_msg(struct airoha_npu *npu, int index,
				   int func_id, u32 *data)
{
	struct wlan_mbox_data *wlan_data;
	int err;

	wlan_data = kzalloc(sizeof(*wlan_data), GFP_KERNEL);
	if (!wlan_data)
		return -ENOMEM;

	wlan_data->ifindex = index;
	wlan_data->func_type = NPU_OP_GET;
	wlan_data->func_id = func_id;

	err = airoha_npu_send_msg(npu, NPU_FUNC_WIFI, wlan_data,
				  sizeof(*wlan_data));
	if (!err)
		*data = wlan_data->data;

	kfree(wlan_data);

	return err;
}

static struct reserved_mem *
airoha_npu_get_reserved_memory(struct airoha_npu *npu, const char *name)
{
	struct device *dev = npu->dev;
	struct reserved_mem *rmem;
	struct device_node *np;
	int index;

	index = of_property_match_string(dev->of_node, "memory-region-names",
					 name);
	if (index < 0)
		return NULL;

	 np = of_parse_phandle(dev->of_node, "memory-region", index);
        if (!np)
                return NULL;

        rmem = of_reserved_mem_lookup(np);
	of_node_put(np);

	return rmem;
}

static int airoha_npu_wlan_set_reserved_memory(struct airoha_npu *npu,
					       int index, const char *name,
					       int func_id)
{
	struct reserved_mem *rmem;

	rmem = airoha_npu_get_reserved_memory(npu, name);
	if (!rmem)
		return -ENODEV;

	return airoha_npu_wlan_send_msg(npu, index, func_id, rmem->base);
}

static int airoha_npu_wlan_set_txrx_reg_addr(struct airoha_npu *npu,
					     int index, u32 dir,
					     u32 in_counter_addr,
					     u32 out_status_addr,
					     u32 out_counter_addr)
{
	struct wlan_mbox_data *wlan_data;
	int err;

	wlan_data = kzalloc(sizeof(*wlan_data), GFP_KERNEL);
	if (!wlan_data)
		return -ENOMEM;

	wlan_data->ifindex = index;
	wlan_data->func_type = NPU_OP_SET;
	wlan_data->func_id = WLAN_FUNC_SET_WAIT_INODE_TXRX_REG_ADDR;
	wlan_data->txrx_addr.dir = dir;
	wlan_data->txrx_addr.in_counter_addr = in_counter_addr;
	wlan_data->txrx_addr.out_status_addr = out_status_addr;
	wlan_data->txrx_addr.out_counter_addr = out_counter_addr;

	err = airoha_npu_send_msg(npu, NPU_FUNC_WIFI, wlan_data,
				  sizeof(*wlan_data));
	kfree(wlan_data);

	return err;
}

static int airoha_npu_wlan_set_pcie_port_type(struct airoha_npu *npu,
					      int index, u32 port_type)
{
	return airoha_npu_wlan_send_msg(npu, index,
					WLAN_FUNC_SET_WAIT_PCIE_PORT_TYPE,
					port_type);
}

static int airoha_npu_wlan_set_dram_ba_node_addr(struct airoha_npu *npu,
						 int index, u32 addr)
{
	return airoha_npu_wlan_send_msg(npu, index,
					WLAN_FUNC_SET_WAIT_DRAM_BA_NODE_ADDR,
					addr);
}

static int airoha_npu_wlan_set_pcie_addr(struct airoha_npu *npu,
					 int index, u32 addr)
{
	return airoha_npu_wlan_send_msg(npu, index,
					WLAN_FUNC_SET_WAIT_PCIE_ADDR, addr);
}

static int airoha_npu_wlan_set_desc(struct airoha_npu *npu, int index,
				    u32 desc)
{
	return airoha_npu_wlan_send_msg(npu, index,
					WLAN_FUNC_SET_WAIT_DESC, desc);
}

static int airoha_npu_wlan_set_tx_ring_pcie_addr(struct airoha_npu *npu,
						 int index, u32 addr)
{
	return airoha_npu_wlan_send_msg(npu, index,
					WLAN_FUNC_SET_WAIT_TX_RING_PCIE_ADDR,
					addr);
}

static int airoha_npu_wlan_get_rx_desc_base(struct airoha_npu *npu, int index,
					    u32 *data)

{
	return airoha_npu_wlan_get_msg(npu, index,
				       WLAN_FUNC_GET_WAIT_RXDESC_BASE, data);
}

static int airoha_npu_wlan_set_tx_buf_space_base(struct airoha_npu *npu,
						 int index, u32 addr)
{
	return airoha_npu_wlan_send_msg(npu, index,
			WLAN_FUNC_SET_WAIT_TX_BUF_SPACE_HW_BASE, addr);
}

static int airoha_npu_wlan_set_rx_ring_for_txdone(struct airoha_npu *npu,
						  int index, u32 addr)
{
	return airoha_npu_wlan_send_msg(npu, index,
			WLAN_FUNC_SET_WAIT_RX_RING_FOR_TXDONE_HW_BASE, addr);
}

static int airoha_npu_wlan_get_npu_support_map(struct airoha_npu *npu,
					       int index, u32 *map)
{
	return airoha_npu_wlan_get_msg(npu, index,
				       WLAN_FUNC_GET_WAIT_NPU_SUPPORT_MAP,
				       map);
}

static int airoha_npu_fill_rx_queue(struct airoha_npu *npu,
				    struct airoha_npu_queue *q)
{
	enum dma_data_direction dir = page_pool_get_dma_dir(q->page_pool);
	int nframes = 0;

	while (q->queued < q->ndesc - 1) {
		struct airoha_npu_rx_dma_desc *desc = &q->desc[q->head];
		struct airoha_npu_queue_entry *e = &q->entry[q->head];
		struct page *page;
		int offset;

		page = page_pool_dev_alloc_frag(q->page_pool, &offset,
						q->buf_size);
		if (!page)
			return -ENOMEM;

		e->buf = page_address(page) + offset;
		e->dma_addr = page_pool_get_dma_addr(page) + offset;
		e->dma_len = SKB_WITH_OVERHEAD(q->buf_size);

		memset(desc, 0, sizeof(*desc));
		desc->addr = e->dma_addr;

		dma_sync_single_for_device(npu->dev, e->dma_addr, e->dma_len,
					   dir);

		q->head = (q->head + 1) % q->ndesc;
		q->queued++;
	}

	return nframes;
}

static struct sk_buff *airoha_npu_rx_dequeue(struct airoha_npu *npu, int qid)
{
	struct airoha_npu_rx_dma_desc *desc;
	struct airoha_npu_queue *q;
	struct sk_buff *skb = NULL;
	int i, nframes, index;

	if (qid >= ARRAY_SIZE(npu->q_rx))
		return NULL;

	q = &npu->q_rx[qid];
	desc = &q->desc[q->tail];
	index = q->tail;

	nframes = FIELD_GET(NPU_RX_DMA_PKT_COUNT_MASK, desc->info);
	nframes = max_t(int, nframes, 1);

	for (i = 0; i < nframes; i++) {
		struct airoha_npu_queue_entry *e = &q->entry[index];
		struct page *page = virt_to_head_page(e->buf);
		int len = FIELD_GET(NPU_RX_DMA_DESC_CUR_LEN_MASK,
				    desc->ctrl);

		if (!FIELD_GET(NPU_RX_DMA_DESC_DONE_MASK, desc->ctrl)) {
			dev_kfree_skb(skb);
			return NULL;
		}

		dma_sync_single_for_cpu(npu->dev, desc->addr,
					SKB_WITH_OVERHEAD(q->buf_size),
					page_pool_get_dma_dir(q->page_pool));

		if (!skb) {
			skb = build_skb(e->buf, q->buf_size);
			if (!skb)
				return NULL;

			__skb_put(skb, len);
			skb_mark_for_recycle(skb);
			skb_reset_mac_header(skb);
		} else {
			struct skb_shared_info *shinfo = skb_shinfo(skb);
			int nr_frags = shinfo->nr_frags;

			if (nr_frags < ARRAY_SIZE(shinfo->frags))
				skb_add_rx_frag(skb, nr_frags, page,
						e->buf - page_address(page),
						len, q->buf_size);
		}

		index = (index + 1) % q->ndesc;
		desc = &q->desc[index];
	}
	q->tail = index;
	q->queued -= i;

	airoha_npu_fill_rx_queue(npu, q);
	regmap_write(npu->regmap, REG_RX_CPU_IDX(qid), q->tail);

	return skb;
}

static int airoha_npu_wlan_init_rx_queue(struct airoha_npu *npu,
					 struct airoha_npu_queue *q)
{
	const struct page_pool_params pp_params = {
		.order = 0,
		.pool_size = 256,
		.flags = PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.dma_dir = DMA_FROM_DEVICE,
		.max_len = PAGE_SIZE,
		.nid = NUMA_NO_NODE,
		.dev = npu->dev,
	};
	struct airoha_npu_rx_dma_desc *rx_desc;
	struct airoha_npu_queue_entry *entry;
	int ndesc, qid = q - &npu->q_rx[0];
	dma_addr_t dma_addr;

	ndesc = qid == 1 ? NPU_RX1_DESC_NUM : NPU_RX0_DESC_NUM;
	rx_desc = dmam_alloc_coherent(npu->dev, ndesc * sizeof(*rx_desc),
				      &dma_addr, GFP_KERNEL);
	if (!rx_desc)
		return -ENOMEM;

	entry = devm_kzalloc(npu->dev, ndesc * sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	q->page_pool = page_pool_create(&pp_params);
	if (IS_ERR(q->page_pool)) {
		int err = PTR_ERR(q->page_pool);

		q->page_pool = NULL;
		return err;
	}

	q->desc = rx_desc;
	q->entry = entry;
	q->ndesc = ndesc;
	q->buf_size = PAGE_SIZE / 2;
	airoha_npu_fill_rx_queue(npu, q);

	regmap_write(npu->regmap, REG_RX_DSCP_NUM(qid), ndesc);
	regmap_write(npu->regmap, REG_RX_CPU_IDX(qid), 0);
	regmap_write(npu->regmap, REG_RX_DMA_IDX(qid), 0);
	regmap_write(npu->regmap, REG_RX_BASE(qid), dma_addr);

	return 0;
}

static void airoha_npu_cleanup_rx_queue(struct airoha_npu *npu,
					struct airoha_npu_queue *q)
{
	while (q->queued) {
		struct airoha_npu_queue_entry *e = &q->entry[q->tail];

		dma_sync_single_for_cpu(npu->dev, e->dma_addr, e->dma_len,
					page_pool_get_dma_dir(q->page_pool));
		page_pool_put_full_page(q->page_pool,
					virt_to_head_page(e->buf),
					false);
		q->tail = (q->tail + 1) % q->ndesc;
		q->queued--;
	}
}

static void airoha_npu_cleanup_rx_queues(struct airoha_npu *npu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(npu->q_rx); i++) {
		airoha_npu_cleanup_rx_queue(npu, &npu->q_rx[i]);
		if (npu->q_rx[i].page_pool)
			page_pool_destroy(npu->q_rx[i].page_pool);
	}
}

static int airoha_npu_wlan_init_txrx_queues(struct airoha_npu *npu)
{
	int i, err = 0;

	for (i = 0; i < ARRAY_SIZE(npu->tx_desc); i++) {
		int ndesc = i ? NPU_TX1_DESC_NUM : NPU_TX0_DESC_NUM;
		struct airoha_npu_tx_dma_desc *tx_desc;
		dma_addr_t dma_addr;
		int qid = 2 + i;

		tx_desc = dmam_alloc_coherent(npu->dev,
					      ndesc * sizeof(*tx_desc),
					      &dma_addr, GFP_KERNEL);
		if (!tx_desc)
			return -ENOMEM;

		npu->tx_desc[i] = tx_desc;

		regmap_write(npu->regmap, REG_TX_DSCP_NUM(qid), ndesc);
		regmap_write(npu->regmap, REG_TX_CPU_IDX(qid), 0);
		regmap_write(npu->regmap, REG_TX_DMA_IDX(qid), 0);
		regmap_write(npu->regmap, REG_TX_BASE(qid), dma_addr);
	}

	for (i = 0; i < ARRAY_SIZE(npu->q_rx); i++) {
		err = airoha_npu_wlan_init_rx_queue(npu, &npu->q_rx[i]);
		if (err)
			goto cleanup_rx_queues;
	}

	return 0;

cleanup_rx_queues:
	airoha_npu_cleanup_rx_queues(npu);

	return err;
}

static int airoha_npu_wlan_init(struct airoha_npu *npu)
{
	int err;

	err = airoha_npu_wlan_init_txrx_queues(npu);
	if (err)
		return err;

	err = airoha_npu_wlan_send_msg(npu, 1,
				       WLAN_FUNC_SET_WAIT_NPU_BAND0_ONCPU, 0);
	if (err)
		goto cleanup_rx_queues;

	err = airoha_npu_wlan_set_reserved_memory(npu, 0, "tx-bufid",
			WLAN_FUNC_SET_WAIT_TX_BUF_CHECK_ADDR);
	if (err)
		goto cleanup_rx_queues;

	err = airoha_npu_wlan_set_reserved_memory(npu, 0, "pkt",
			WLAN_FUNC_SET_WAIT_PKT_BUF_ADDR);
	if (err)
		goto cleanup_rx_queues;

	err = airoha_npu_wlan_set_reserved_memory(npu, 0, "tx-pkt",
			WLAN_FUNC_SET_WAIT_TX_PKT_BUF_ADDR);
	if (err)
		goto cleanup_rx_queues;

	err = airoha_npu_wlan_send_msg(npu, 0,
				       WLAN_FUNC_SET_WAIT_IS_FORCE_TO_CPU, 0);
	if (err)
		goto cleanup_rx_queues;

	return 0;

cleanup_rx_queues:
	airoha_npu_cleanup_rx_queues(npu);

	return err;
}

static void airoha_npu_wlan_set_irq_mask(struct airoha_npu *npu, int q)
{
	/* FIXME */
	regmap_set_bits(npu->regmap, REG_IRQ_STATUS, NPU_IRQ_RX_MASK(q));
}

static u32 airoha_npu_wlan_get_irq(struct airoha_npu *npu, int q)
{
	/* FIXME */
	u32 val;

	regmap_read(npu->regmap, REG_IRQ_STATUS, &val);
	return val;
}

static void airoha_npu_wlan_irq_enable(struct airoha_npu *npu, int q)
{
	regmap_set_bits(npu->regmap, REG_IRQ_RXDONE(q), NPU_IRQ_RX_MASK(q));
}

static void airoha_npu_wlan_irq_disable(struct airoha_npu *npu, int q)
{
	regmap_clear_bits(npu->regmap, REG_IRQ_RXDONE(q), NPU_IRQ_RX_MASK(q));
}

struct airoha_npu *airoha_npu_get(struct device *dev)
{
	struct platform_device *pdev;
	struct device_node *np;
	struct airoha_npu *npu;

	np = of_parse_phandle(dev->of_node, "airoha,npu", 0);
	if (!np)
		return ERR_PTR(-ENODEV);

	pdev = of_find_device_by_node(np);
	of_node_put(np);

	if (!pdev) {
		dev_err(dev, "cannot find device node %s\n", np->name);
		return ERR_PTR(-ENODEV);
	}

	if (!try_module_get(THIS_MODULE)) {
		dev_err(dev, "failed to get the device driver module\n");
		npu = ERR_PTR(-ENODEV);
		goto error_pdev_put;
	}

	npu = platform_get_drvdata(pdev);
	if (!npu) {
		npu = ERR_PTR(-ENODEV);
		goto error_module_put;
	}

	if (!device_link_add(dev, &pdev->dev, DL_FLAG_AUTOREMOVE_SUPPLIER)) {
		dev_err(&pdev->dev,
			"failed to create device link to consumer %s\n",
			dev_name(dev));
		npu = ERR_PTR(-EINVAL);
		goto error_module_put;
	}

	return npu;

error_module_put:
	module_put(THIS_MODULE);
error_pdev_put:
	platform_device_put(pdev);

	return npu;
}
EXPORT_SYMBOL_GPL(airoha_npu_get);

void airoha_npu_put(struct airoha_npu *npu)
{
	module_put(THIS_MODULE);
	put_device(npu->dev);
}
EXPORT_SYMBOL_GPL(airoha_npu_put);

static const struct of_device_id of_airoha_npu_match[] = {
	{ .compatible = "airoha,en7581-npu" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_airoha_npu_match);

static const struct regmap_config regmap_config = {
	.name			= "npu",
	.reg_bits		= 32,
	.val_bits		= 32,
	.reg_stride		= 4,
	.disable_locking	= true,
};

static int airoha_npu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct reserved_mem *rmem;
	struct airoha_npu *npu;
	struct device_node *np;
	void __iomem *base;
	int i, irq, err;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	npu = devm_kzalloc(dev, sizeof(*npu), GFP_KERNEL);
	if (!npu)
		return -ENOMEM;

	npu->dev = dev;
	npu->ops.ppe_init = airoha_npu_ppe_init;
	npu->ops.ppe_deinit = airoha_npu_ppe_deinit;
	npu->ops.ppe_flush_sram_entries = airoha_npu_ppe_flush_sram_entries;
	npu->ops.ppe_foe_commit_entry = airoha_npu_foe_commit_entry;
	npu->ops.wlan_set_txrx_reg_addr = airoha_npu_wlan_set_txrx_reg_addr;
	npu->ops.wlan_set_pcie_port_type = airoha_npu_wlan_set_pcie_port_type;
	npu->ops.wlan_set_dram_ba_node_addr =
		airoha_npu_wlan_set_dram_ba_node_addr;
	npu->ops.wlan_set_pcie_addr = airoha_npu_wlan_set_pcie_addr;
	npu->ops.wlan_set_desc = airoha_npu_wlan_set_desc;
	npu->ops.wlan_set_tx_ring_pcie_addr =
		airoha_npu_wlan_set_tx_ring_pcie_addr;
	npu->ops.wlan_get_rx_desc_base = airoha_npu_wlan_get_rx_desc_base;
	npu->ops.wlan_set_tx_buf_space_base =
		airoha_npu_wlan_set_tx_buf_space_base;
	npu->ops.wlan_set_rx_ring_for_txdone =
		airoha_npu_wlan_set_rx_ring_for_txdone;
	npu->ops.wlan_get_npu_support_map =
		airoha_npu_wlan_get_npu_support_map;
	npu->ops.wlan_rx_dequeue = airoha_npu_rx_dequeue;
	npu->ops.wlan_set_irq_mask = airoha_npu_wlan_set_irq_mask;
	npu->ops.wlan_get_irq = airoha_npu_wlan_get_irq;
	npu->ops.wlan_irq_enable = airoha_npu_wlan_irq_enable;
	npu->ops.wlan_irq_disable = airoha_npu_wlan_irq_disable;

	npu->regmap = devm_regmap_init_mmio(dev, base, &regmap_config);
	if (IS_ERR(npu->regmap))
		return PTR_ERR(npu->regmap);

	np = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!np)
		return -ENODEV;

	rmem = of_reserved_mem_lookup(np);
	of_node_put(np);

	if (!rmem)
		return -ENODEV;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	err = devm_request_irq(dev, irq, airoha_npu_mbox_handler,
			       IRQF_SHARED, "airoha-npu-mbox", npu);
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(npu->cores); i++) {
		struct airoha_npu_core *core = &npu->cores[i];

		spin_lock_init(&core->lock);
		core->npu = npu;

		irq = platform_get_irq(pdev, i + 1);
		if (irq < 0)
			return irq;

		err = devm_request_irq(dev, irq, airoha_npu_wdt_handler,
				       IRQF_SHARED, "airoha-npu-wdt", core);
		if (err)
			return err;

		INIT_WORK(&core->wdt_work, airoha_npu_wdt_work);
	}

	for (i = 0; i < ARRAY_SIZE(npu->irqs); i++) {
		irq = platform_get_irq(pdev, i + ARRAY_SIZE(npu->cores) + 1);
		if (irq < 0)
			return irq;

		npu->irqs[i] = irq;
	}

	err = dma_set_coherent_mask(dev, DMA_BIT_MASK(32));
	if (err)
		return err;

	err = airoha_npu_run_firmware(dev, base, rmem);
	if (err)
		return dev_err_probe(dev, err, "failed to run npu firmware\n");

	regmap_write(npu->regmap, REG_CR_NPU_MIB(10),
		     rmem->base + NPU_EN7581_FIRMWARE_RV32_MAX_SIZE);
	regmap_write(npu->regmap, REG_CR_NPU_MIB(11), 0x40000); /* SRAM 256K */
	regmap_write(npu->regmap, REG_CR_NPU_MIB(12), 0);
	regmap_write(npu->regmap, REG_CR_NPU_MIB(21), 1);
	msleep(100);

	/* setting booting address */
	for (i = 0; i < NPU_NUM_CORES; i++)
		regmap_write(npu->regmap, REG_CR_BOOT_BASE(i), rmem->base);
	usleep_range(1000, 2000);

	/* enable NPU cores */
	regmap_write(npu->regmap, REG_CR_BOOT_CONFIG, 0xff);
	regmap_write(npu->regmap, REG_CR_BOOT_TRIGGER, 0x1);
	msleep(100);

	err = airoha_npu_wlan_init(npu);
	if (err)
		return err;

	platform_set_drvdata(pdev, npu);

	return 0;
}

static void airoha_npu_remove(struct platform_device *pdev)
{
	struct airoha_npu *npu = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < ARRAY_SIZE(npu->cores); i++)
		cancel_work_sync(&npu->cores[i].wdt_work);

	airoha_npu_cleanup_rx_queues(npu);
}

static struct platform_driver airoha_npu_driver = {
	.probe = airoha_npu_probe,
	.remove = airoha_npu_remove,
	.driver = {
		.name = "airoha-npu",
		.of_match_table = of_airoha_npu_match,
	},
};
module_platform_driver(airoha_npu_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lorenzo Bianconi <lorenzo@kernel.org>");
MODULE_DESCRIPTION("Airoha Network Processor Unit driver");
