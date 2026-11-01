"""二进制传感器：滤芯到期、缺水、水泵堵塞、水质异常、童锁等."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import HiiggeCoordinator
from .entity import HiiggeEntity


@dataclass(frozen=True, kw_only=True)
class HiiggeBinaryDescription(BinarySensorEntityDescription):
    field: str


BINARY_SENSORS: tuple[HiiggeBinaryDescription, ...] = (
    HiiggeBinaryDescription(
        key="filter_expired", field="filter_expired", name="滤芯到期",
        device_class=BinarySensorDeviceClass.PROBLEM, icon="mdi:air-filter",
    ),
    HiiggeBinaryDescription(
        key="water_volume_low", field="water_volume_low", name="缺水",
        device_class=BinarySensorDeviceClass.PROBLEM, icon="mdi:water-alert",
    ),
    HiiggeBinaryDescription(
        key="water_quality_abnormal", field="water_quality_abnormal", name="水质异常",
        device_class=BinarySensorDeviceClass.PROBLEM, icon="mdi:water-check-alert",
    ),
    HiiggeBinaryDescription(
        key="pump_block", field="water_pump_block", name="水泵堵塞",
        device_class=BinarySensorDeviceClass.PROBLEM, icon="mdi:pump-off",
    ),
    # 童锁 / 强力冲刷已升级为可写 switch（见 switch.py），这里不再重复只读实体
    HiiggeBinaryDescription(
        key="quiet", field="quiet_mode_enabled", name="夜间免打扰",
        icon="mdi:weather-night", entity_category=EntityCategory.DIAGNOSTIC,
    ),
    HiiggeBinaryDescription(
        key="uv", field="uv_enabled", name="UV 杀菌",
        icon="mdi:lightbulb-on-outline", entity_category=EntityCategory.DIAGNOSTIC,
    ),
    # 充电状态来自 Battery.charge_status（1=CHARGING 才为 on）；
    # FULL（已充满）与 NOT_CHARGING 都为 off，具体差异看「充电状态」传感器
    HiiggeBinaryDescription(
        key="battery_charging", field="battery_charging", name="充电中",
        device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
        icon="mdi:battery-charging",
    ),
    # 同一枚举的另一种解读：CHARGING + FULL 都代表电源线接着，只有 NOT_CHARGING 才算断开。
    # 插电常满的饮水机读数是 FULL，此时「充电中」为关，用这个实体判断是否接着电源。
    HiiggeBinaryDescription(
        key="power_connected", field="power_connected", name="是否连接电源",
        device_class=BinarySensorDeviceClass.PLUG, icon="mdi:power-plug",
    ),
    HiiggeBinaryDescription(
        key="led_quiet", field="led_quiet_enabled", name="灯光静音",
        icon="mdi:led-off", entity_category=EntityCategory.DIAGNOSTIC,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: HiiggeCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = [
        HiiggeBinarySensor(coordinator, dev.device_id, desc)
        for dev in coordinator.data.devices
        for desc in BINARY_SENSORS
        if dev.status.get(desc.field) is not None
    ]
    async_add_entities(entities)


class HiiggeBinarySensor(HiiggeEntity, BinarySensorEntity):
    entity_description: HiiggeBinaryDescription

    def __init__(
        self, coordinator: HiiggeCoordinator, device_id: str, description: HiiggeBinaryDescription
    ) -> None:
        super().__init__(coordinator, device_id, description.key)
        self.entity_description = description
        self._attr_unique_id = f"{device_id}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        value = self.status_value(self.entity_description.field)
        return None if value is None else bool(value)
