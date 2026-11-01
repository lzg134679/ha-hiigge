"""实体基类."""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import HiiggeDevice
from .const import DOMAIN
from .coordinator import MISSING, HiiggeCoordinator


class HiiggeEntity(CoordinatorEntity[HiiggeCoordinator]):
    """所有 Hiigge 实体的公共部分."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: HiiggeCoordinator, device_id: str, key: str) -> None:
        super().__init__(coordinator)
        self._device_id = device_id
        self._key = key

    @property
    def device(self) -> HiiggeDevice | None:
        return self.coordinator.data.by_id(self._device_id) if self.coordinator.data else None

    @property
    def status(self) -> dict[str, Any]:
        dev = self.device
        return dev.status if dev else {}

    @property
    def available(self) -> bool:
        return super().available and self.device is not None

    def status_value(self, key: str) -> Any:
        """读一个设备状态字段.

        故意不叫 `value`：HA 的 NumberEntity 把 `value` 定义成只读属性，
        基类若有同名方法会在 MRO 中遮蔽它，导致控件状态计算拿到 bound method
        （线上表现为 RecursionError、实体加不进来）。

        写操作刚下发、设备还没回读确认时，这里返回期望值，避免界面先闪回旧值。
        抑制窗口见 `coordinator.expect_state`。
        """
        pending = self.coordinator.expected_value(key)
        return self.status.get(key) if pending is MISSING else pending

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """写操作等待设备回读期间打标记，便于排查"改完迟迟不生效"."""
        if self.coordinator.is_pending(self._key):
            return {"pending": True}
        return {}

    @property
    def device_info(self) -> DeviceInfo:
        dev = self.device
        raw = dev.raw if dev else {}
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_id)},
            manufacturer="Hiigge",
            model=str(raw.get("model") or raw.get("module") or "宠物饮水机"),
            name=dev.name if dev else self._device_id,
            serial_number=str(raw.get("sn") or self._device_id),
            sw_version=str(raw.get("softwareVersionNumber") or "") or None,
            hw_version=str(raw.get("module") or "") or None,
        )
