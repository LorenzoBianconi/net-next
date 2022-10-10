// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Lorenzo Bianconi <lorenzo@kernel.org>  */

#include <linux/firmware.h>
#include <linux/of_address.h>
#include <linux/mfd/syscon.h>
#include <linux/soc/mediatek/mtk_wed.h>
#include <asm/unaligned.h>

#include "mtk_wed_regs.h"
#include "mtk_wed_wo.h"
#include "mtk_wed.h"

static u32 wo_r32(struct mtk_wed_wo *wo, u32 reg)
{
	u32 val;

	if (regmap_read(wo->boot, reg, &val))
		val = ~0;

	return val;
}

static void wo_w32(struct mtk_wed_wo *wo, u32 reg, u32 val)
{
	regmap_write(wo->boot, reg, val);
}

static struct sk_buff *
mtk_wed_mcu_msg_alloc(const void *data, int data_len)
{
	int length = sizeof(struct mtk_wed_mcu_hdr) + data_len;
	struct sk_buff *skb;

	skb = alloc_skb(length, GFP_KERNEL);
	if (!skb)
		return NULL;

	memset(skb->head, 0, length);
	skb_reserve(skb, sizeof(struct mtk_wed_mcu_hdr));
	if (data && data_len)
		skb_put_data(skb, data, data_len);

	return skb;
}

static struct sk_buff *
mtk_wed_mcu_get_response(struct mtk_wed_wo *wo, unsigned long expires)
{
	if (!time_is_after_jiffies(expires))
		return NULL;

	wait_event_timeout(wo->mcu.wait, !skb_queue_empty(&wo->mcu.res_q),
			   expires - jiffies);
	return skb_dequeue(&wo->mcu.res_q);
}

void mtk_wed_mcu_rx_event(struct mtk_wed_wo *wo, struct sk_buff *skb)
{
	skb_queue_tail(&wo->mcu.res_q, skb);
	wake_up(&wo->mcu.wait);
}

static void
mtk_wed_update_rx_stats(struct mtk_wed_device *wed, struct sk_buff *skb)
{
	u32 count = get_unaligned_le32(skb->data);
	struct mtk_wed_wo_rx_stats *stats;
	int i;

	if (count * sizeof(*stats) > skb->len - sizeof(u32))
		return;

	stats = (struct mtk_wed_wo_rx_stats *)(skb->data + sizeof(u32));
	for (i = 0 ; i < count ; i++)
		wed->wlan.update_wo_rx_stats(wed, &stats[i]);
}

void mtk_wed_mcu_rx_unsolicited_event(struct mtk_wed_wo *wo,
				      struct sk_buff *skb)
{
	struct mtk_wed_mcu_hdr *hdr = (struct mtk_wed_mcu_hdr *)skb->data;

	skb_pull(skb, sizeof(*hdr));

	switch (hdr->cmd) {
	case MTK_WED_WO_EVT_LOG_DUMP:
		dev_notice(wo->hw->dev, "%s\n", skb->data);
		break;
	case MTK_WED_WO_EVT_PROFILING: {
		struct mtk_wed_wo_log_info *info = (void *)skb->data;
		u32 count = skb->len / sizeof(*info);
		int i;

		for (i = 0 ; i < count ; i++)
			dev_notice(wo->hw->dev,
				   "SN:%u latency: total=%u, rro:%u, mod:%u\n",
				   le32_to_cpu(info[i].sn),
				   le32_to_cpu(info[i].total),
				   le32_to_cpu(info[i].rro),
				   le32_to_cpu(info[i].mod));
		break;
	}
	case MTK_WED_WO_EVT_RXCNT_INFO:
		mtk_wed_update_rx_stats(wo->hw->wed_dev, skb);
		break;
	default:
		break;
	}

	dev_kfree_skb(skb);
}

static int
mtk_wed_mcu_skb_send_msg(struct mtk_wed_wo *wo, struct sk_buff *skb,
			 int id, int cmd, u16 *wait_seq, bool wait_resp)
{
	struct mtk_wed_mcu_hdr *hdr;

	/* TODO: make it dynamic based on cmd */
	wo->mcu.timeout = 20 * HZ;

	hdr = (struct mtk_wed_mcu_hdr *)skb_push(skb, sizeof(*hdr));
	hdr->cmd = cmd;
	hdr->length = cpu_to_le16(skb->len);

	if (wait_resp && wait_seq) {
		u16 seq = ++wo->mcu.seq;

		if (!seq)
			seq = ++wo->mcu.seq;
		*wait_seq = seq;

		hdr->flag |= cpu_to_le16(MTK_WED_WARP_CMD_FLAG_NEED_RSP);
		hdr->seq = cpu_to_le16(seq);
	}
	if (id == MTK_WED_MODULE_ID_WO)
		hdr->flag |= cpu_to_le16(MTK_WED_WARP_CMD_FLAG_FROM_TO_WO);

	return mtk_wed_wo_queue_tx_skb(wo, &wo->q_tx, skb);
}

static int
mtk_wed_mcu_parse_response(struct mtk_wed_wo *wo, struct sk_buff *skb,
			   int cmd, int seq)
{
	struct mtk_wed_mcu_hdr *hdr;

	if (!skb) {
		dev_err(wo->hw->dev, "Message %08x (seq %d) timeout\n",
			cmd, seq);
		return -ETIMEDOUT;
	}

	hdr = (struct mtk_wed_mcu_hdr *)skb->data;
	if (le16_to_cpu(hdr->seq) != seq)
		return -EAGAIN;

	skb_pull(skb, sizeof(*hdr));
	switch (cmd) {
	case MTK_WED_WO_CMD_RXCNT_INFO:
		mtk_wed_update_rx_stats(wo->hw->wed_dev, skb);
		break;
	default:
		break;
	}

	return 0;
}

int mtk_wed_mcu_send_msg(struct mtk_wed_wo *wo, int id, int cmd,
			 const void *data, int len, bool wait_resp)
{
	unsigned long expires;
	struct sk_buff *skb;
	u16 seq;
	int ret;

	skb = mtk_wed_mcu_msg_alloc(data, len);
	if (!skb)
		return -ENOMEM;

	mutex_lock(&wo->mcu.mutex);

	ret = mtk_wed_mcu_skb_send_msg(wo, skb, id, cmd, &seq, wait_resp);
	if (ret || !wait_resp)
		goto unlock;

	expires = jiffies + wo->mcu.timeout;
	do {
		skb = mtk_wed_mcu_get_response(wo, expires);
		ret = mtk_wed_mcu_parse_response(wo, skb, cmd, seq);
		dev_kfree_skb(skb);
	} while (ret == -EAGAIN);

unlock:
	mutex_unlock(&wo->mcu.mutex);

	return ret;
}

int mtk_wed_mcu_msg_update(struct mtk_wed_device *dev, int id, void *data,
			   int len)
{
	struct mtk_wed_wo *wo = dev->hw->wed_wo;

	if (dev->hw->version == 1)
		return 0;

	return mtk_wed_mcu_send_msg(wo, MTK_WED_MODULE_ID_WO, id, data, len,
				    true);
}

static int
mtk_wed_get_firmware_metadata(struct mtk_wed_wo *wo,
			      struct mtk_wed_fw_region_meta *meta)
{
	struct device_node *np;
	struct resource res;
	int ret;

	np = of_parse_phandle(wo->hw->node, meta->name, 0);
	if (!np)
		return -ENODEV;

	ret = of_address_to_resource(np, 0, &res);
	if (ret)
		goto out;

	meta->phy_addr = res.start;
	meta->size = resource_size(&res);
	meta->addr = devm_ioremap(wo->hw->dev, res.start, meta->size);
	if (!meta->addr)
		ret = -ENOMEM;
out:
	of_node_put(np);

	return ret;
}

static int
mtk_wed_mcu_load_firmware(struct mtk_wed_wo *wo)
{
	static struct mtk_wed_fw_region_meta fw_region[] = {
		[MTK_WED_WO_FW_EMI] = {
			.name = "mediatek,wocpu_emi",
		},
		[MTK_WED_WO_FW_ILM] = {
			.name = "mediatek,wocpu_ilm",
		},
		[MTK_WED_WO_FW_DATA] = {
			.name = "mediatek,wocpu_data",
			.shared = true,
		},
	};
	const struct mtk_wed_fw_trailer *trailer;
	const struct mtk_wed_fw_region *region;
	const u8 *region_ptr, *trailer_ptr;
	u32 val, offset = 0, boot_cr;
	const struct firmware *fw;
	int ret, i, count = 0;
	const char *fw_name;

	/* load firmware region metadata */
	for (i = 0; i < ARRAY_SIZE(fw_region); i++) {
		ret = mtk_wed_get_firmware_metadata(wo, &fw_region[i]);
		if (ret)
			return ret;
	}

	wo->boot = syscon_regmap_lookup_by_phandle(wo->hw->node,
						   "mediatek,wocpu_boot");
	if (IS_ERR_OR_NULL(wo->boot))
		return PTR_ERR(wo->boot);

	/* set dummy cr */
	wed_w32(wo->hw->wed_dev, MTK_WED_SCR0 + 4 * MTK_WED_DUMMY_CR_FWDL,
		wo->hw->index + 1);

	/* load firmware */
	fw_name = wo->hw->index ? MT7986_FIRMWARE_WO1 : MT7986_FIRMWARE_WO0;
	ret = request_firmware(&fw, fw_name, wo->hw->dev);
	if (ret)
		return ret;

	trailer_ptr = fw->data + fw->size - sizeof(*trailer);
	trailer = (const struct mtk_wed_fw_trailer *)trailer_ptr;
	dev_info(wo->hw->dev,
		 "MTK WED WO Firmware Version: %.10s, Build Time: %.15s\n",
		 trailer->fw_ver, trailer->build_date);
	dev_info(wo->hw->dev, "MTK WED WO Chid ID %02x Region %d\n",
		 trailer->chip_id, trailer->num_region);

	if (fw->size - sizeof(*trailer) < trailer->num_region * sizeof(*region)) {
		dev_err(wo->hw->dev, "Invalid fw num_region %d\n",
			trailer->num_region);
		ret = -EINVAL;
		goto out;
	}

	region_ptr = trailer_ptr - trailer->num_region * sizeof(*region);
	while (region_ptr < trailer_ptr) {
		int j;

		region = (const struct mtk_wed_fw_region *)region_ptr;
		for (j = 0; j < ARRAY_SIZE(fw_region); j++) {
			if (fw_region[j].phy_addr != region->addr)
				continue;

			if (fw_region[j].size < region->len)
				continue;

			if (trailer_ptr < fw->data + offset + region->len)
				continue;

			if (!fw_region[j].shared || !fw_region[j].consumed) {
				memcpy(fw_region[j].addr, fw->data + offset,
				       region->len);
				fw_region[j].consumed = true;
				count++;
			} else if (fw_region[j].shared) {
				count++;
			}
		}
		region_ptr += sizeof(*region);
		offset += region->len;
	}

	if (count != ARRAY_SIZE(fw_region)) {
		dev_err(wo->hw->dev, "Failed to load firmware\n");
		ret = -EINVAL;
		goto out;
	}

	/* set the start address */
	boot_cr = wo->hw->index ? MTK_WO_MCU_CFG_LS_WA_BOOT_ADDR_ADDR
				: MTK_WO_MCU_CFG_LS_WM_BOOT_ADDR_ADDR;
	wo_w32(wo, boot_cr, fw_region[MTK_WED_WO_FW_EMI].phy_addr >> 16);
	/* wo firmware reset */
	wo_w32(wo, MTK_WO_MCU_CFG_LS_WF_MCCR_CLR_ADDR, 0xc00);

	val = wo_r32(wo, MTK_WO_MCU_CFG_LS_WF_MCU_CFG_WM_WA_ADDR);
	val |= wo->hw->index ? MTK_WO_MCU_CFG_LS_WF_WM_WA_WA_CPU_RSTB_MASK
			     : MTK_WO_MCU_CFG_LS_WF_WM_WA_WM_CPU_RSTB_MASK;
	wo_w32(wo, MTK_WO_MCU_CFG_LS_WF_MCU_CFG_WM_WA_ADDR, val);
out:
	release_firmware(fw);

	return ret;
}

int mtk_wed_mcu_init(struct mtk_wed_wo *wo)
{
	u32 val;
	int ret;

	skb_queue_head_init(&wo->mcu.res_q);
	init_waitqueue_head(&wo->mcu.wait);
	mutex_init(&wo->mcu.mutex);

	ret = mtk_wed_mcu_load_firmware(wo);
	if (ret)
		return ret;

	do {
		/* get dummy cr */
		val = wed_r32(wo->hw->wed_dev,
			      MTK_WED_SCR0 + 4 * MTK_WED_DUMMY_CR_FWDL);
	} while (val && !time_after(jiffies, jiffies + MTK_FW_DL_TIMEOUT));

	return val ? -EBUSY : 0;
}

MODULE_FIRMWARE(MT7986_FIRMWARE_WO0);
MODULE_FIRMWARE(MT7986_FIRMWARE_WO1);
