/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 AIROHA Inc
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 */

#ifndef AIROHA_NPU_H
#define AIROHA_NPU_H

#define NPU_NUM_CORES		8
#define NPU_NUM_IRQ		6
#define NPU_NUM_RXQ		2
#define NPU_RX0_DESC_NUM	512
#define NPU_RX1_DESC_NUM	512

/* CTRL */
#define NPU_RX_DMA_DESC_LAST_MASK	BIT(29)
#define NPU_RX_DMA_DESC_LEN_MASK	GENMASK(28, 15)
#define NPU_RX_DMA_DESC_CUR_LEN_MASK	GENMASK(14, 1)
#define NPU_RX_DMA_DESC_DONE_MASK	BIT(0)
/* INFO */
#define NPU_RX_DMA_PKT_COUNT_MASK	GENMASK(31, 28)
#define NPU_RX_DMA_PKT_ID_MASK		GENMASK(28, 26)
#define NPU_RX_DMA_SRC_PORT_MASK	GENMASK(25, 21)
#define NPU_RX_DMA_CRSN_MASK		GENMASK(20, 16)
#define NPU_RX_DMA_FOE_ID_MASK		GENMASK(15, 0)
/* DATA */
#define NPU_RX_DMA_SID_MASK		GENMASK(31, 16)
#define NPU_RX_DMA_FRAG_TYPE_MASK	GENMASK(15, 14)
#define NPU_RX_DMA_PRIORITY_MASK	GENMASK(13, 10)
#define NPU_RX_DMA_RADIO_ID_MASK	GENMASK(9, 6)
#define NPU_RX_DMA_VAP_ID_MASK		GENMASK(5, 2)
#define NPU_RX_DMA_FRAME_TYPE_MASK	GENMASK(1, 0)

struct airoha_npu_rx_dma_desc {
	u32 ctrl;
	u32 info;
	u32 data;
	u32 addr;
	u64 rsv;
} __packed;

struct airoha_npu_tx_dma_desc {
	u32 ctrl;
	u32 addr;
	u64 rsv;
	u8 data[192];
} __packed;

struct airoha_npu_queue_entry {
	void *buf;
	dma_addr_t dma_addr;
	u16 dma_len;
};

struct airoha_npu_queue {
	u16 head;
	u16 tail;

	int queued;
	int ndesc;
	int buf_size;

	struct airoha_npu_queue_entry *entry;
	struct airoha_npu_rx_dma_desc *desc;
	struct page_pool *page_pool;
};

struct airoha_npu {
#if (IS_BUILTIN(CONFIG_NET_AIROHA_NPU) || IS_MODULE(CONFIG_NET_AIROHA_NPU))
	struct device *dev;
	struct regmap *regmap;

	struct airoha_npu_core {
		struct airoha_npu *npu;
		/* protect concurrent npu memory accesses */
		spinlock_t lock;
		struct work_struct wdt_work;
	} cores[NPU_NUM_CORES];

	int irqs[NPU_NUM_IRQ];

	struct airoha_npu_queue q_rx[NPU_NUM_RXQ];

	struct {
		int (*ppe_init)(struct airoha_npu *npu);
		int (*ppe_deinit)(struct airoha_npu *npu);
		int (*ppe_flush_sram_entries)(struct airoha_npu *npu,
					      dma_addr_t foe_addr,
					      int sram_num_entries);
		int (*ppe_foe_commit_entry)(struct airoha_npu *npu,
					    dma_addr_t foe_addr,
					    u32 entry_size, u32 hash,
					    bool ppe2);
		int (*wlan_set_txrx_reg_addr)(struct airoha_npu *npu,
					      int index, u32 dir,
					      u32 in_counter_addr,
					      u32 out_status_addr,
					      u32 out_counter_addr);
		int (*wlan_set_pcie_port_type)(struct airoha_npu *npu,
					       int index, u32 port_type);
		int (*wlan_set_dram_ba_node_addr)(struct airoha_npu *npu,
						  int index, u32 addr);
		int (*wlan_set_pcie_addr)(struct airoha_npu *npu, int index,
					  u32 addr);
		int (*wlan_set_desc)(struct airoha_npu *npu, int index,
				     u32 desc);
		int (*wlan_set_tx_ring_pcie_addr)(struct airoha_npu *npu,
						  int index, u32 addr);
		int (*wlan_get_rx_desc_base)(struct airoha_npu *npu,
					     int index, u32 *data);
		int (*wlan_set_tx_buf_space_base)(struct airoha_npu *npu,
						  int index, u32 addr);
		int (*wlan_set_rx_ring_for_txdone)(struct airoha_npu *npu,
						   int index, u32 addr);
		int (*wlan_get_npu_support_map)(struct airoha_npu *npu,
						int index, u32 *map);
		struct sk_buff *(*wlan_rx_dequeue)(struct airoha_npu *npu,
						   int index);
		void (*wlan_set_irq_mask)(struct airoha_npu *npu, int q);
		u32 (*wlan_get_irq)(struct airoha_npu *npu, int q);
		void (*wlan_irq_enable)(struct airoha_npu *npu, int q);
		void (*wlan_irq_disable)(struct airoha_npu *npu, int q);
	} ops;
#endif
};

static inline bool airoha_npu_device_active(struct airoha_npu *npu)
{
	return !!npu;
}

#if (IS_BUILTIN(CONFIG_NET_AIROHA_NPU) || IS_MODULE(CONFIG_NET_AIROHA_NPU))
struct airoha_npu *airoha_npu_get(struct device *dev);
void airoha_npu_put(struct airoha_npu *npu);
#else
static inline struct airoha_npu *airoha_npu_get(struct device *dev)
{
	return NULL;
}

static inline void airoha_npu_put(struct airoha_npu *npu)
{
}
#endif

#endif /* AIROHA_NPU_H */
