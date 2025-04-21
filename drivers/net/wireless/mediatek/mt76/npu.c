// SPDX-License-Identifier: ISC
/*
 * Copyright (C) 2025 Lorenzo Bianconi <lorenzo@kernel.org>
 */
#include "mt76.h"

int mt76_npu_init(struct mt76_dev *dev)
{
	struct airoha_npu *npu;
	int err = 0;

	mutex_lock(&dev->mutex);

	npu = airoha_npu_get(dev->dev);
	if (IS_ERR(npu)) {
		request_module("airoha-npu");
		npu = airoha_npu_get(dev->dev);
	}

	if (IS_ERR(npu)) {
		err = PTR_ERR(npu);
		goto unlock;
	}

	rcu_assign_pointer(dev->mmio.npu, npu);
	synchronize_rcu();
unlock:
	mutex_unlock(&dev->mutex);

	return err;
}
EXPORT_SYMBOL_GPL(mt76_npu_init);

void mt76_npu_deinit(struct mt76_dev *dev)
{
	struct airoha_npu *npu;

	mutex_lock(&dev->mutex);

	npu = rcu_replace_pointer(dev->mmio.npu, NULL,
				  lockdep_is_held(&dev->mutex));
	if (npu)
		airoha_npu_put(npu);

	mutex_unlock(&dev->mutex);
}
EXPORT_SYMBOL_GPL(mt76_npu_deinit);
