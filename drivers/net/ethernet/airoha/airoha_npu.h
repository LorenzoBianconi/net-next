/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 AIROHA Inc
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 */

#define NPU_NUM_CORES		8

struct airoha_npu {
	struct device *dev;
	struct regmap *regmap;

	struct airoha_npu_core {
		struct airoha_npu *npu;
		/* protect concurrent npu memory accesses */
		spinlock_t lock;
		struct work_struct wdt_work;
	} cores[NPU_NUM_CORES];

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
	} ops;
};

static inline bool airoha_npu_device_active(struct airoha_npu *npu)
{
	return !!npu;
}

struct airoha_npu *airoha_npu_get(struct device *dev);
void airoha_npu_put(struct airoha_npu *npu);
