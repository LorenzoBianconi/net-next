/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 AIROHA Inc
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 */

#define NPU_NUM_CORES		8
#define NPU_RX0_DESC_NUM	512
#define NPU_RX1_DESC_NUM	512
#define NPU_RX_DESC_NUM		(NPU_RX0_DESC_NUM + NPU_RX1_DESC_NUM)
#define NPU_TX0_DESC_NUM	1024
#define NPU_TX1_DESC_NUM	1024
#define NPU_TX_DESC_NUM		(NPU_TX0_DESC_NUM + NPU_TX1_DESC_NUM)

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
	} ops;

	void *tx_desc;
	struct {
		void *desc;
		struct page *page_list[NPU_RX_DESC_NUM];
	} rx;
};

struct airoha_npu *airoha_npu_get(struct device *dev);
void airoha_npu_put(struct airoha_npu *npu);
