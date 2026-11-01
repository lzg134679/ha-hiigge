"""按钮：重置滤芯 / 清除缺水提示（前者走 WebSocket，后者走 REST）."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import HiiggeCoordinator
from .entity import HiiggeEntity
from .ws import cmd_filter_reset


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    bucket = hass.data[DOMAIN][entry.entry_id]
    if not bucket.get("enable_control", True):
        return
    coordinator: HiiggeCoordinator = bucket["coordinator"]
    async_add_entities(
        entity
        for dev in coordinator.data.devices
        for entity in (
            HiiggeFilterResetButton(coordinator, dev.device_id),
            HiiggeClearWaterLowButton(coordinator, dev.device_id),
        )
    )


class HiiggeFilterResetButton(HiiggeEntity, ButtonEntity):
    """滤芯重置——协议实测：裸 SmartPacket{type:49, id:11}."""

    _attr_name = "重置滤芯"
    _attr_icon = "mdi:air-filter"

    def __init__(self, coordinator: HiiggeCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "filter_reset")
        self._attr_unique_id = f"{device_id}_filter_reset"

    async def async_press(self, **kwargs) -> None:
        try:
            await self.coordinator.async_send_command(cmd_filter_reset())
        except Exception as err:  # noqa: BLE001
            raise HomeAssistantError(f"重置滤芯失败: {err}") from err


class HiiggeClearWaterLowButton(HiiggeEntity, ButtonEntity):
    _attr_name = "清除缺水提示"
    _attr_icon = "mdi:water-alert"

    def __init__(self, coordinator: HiiggeCoordinator, device_id: str) -> None:
        super().__init__(coordinator, device_id, "clear_water_low")
        self._attr_unique_id = f"{device_id}_clear_water_low"

    async def async_press(self, **kwargs) -> None:
        try:
            await self.coordinator.async_clear_water_low()
        except Exception as err:  # noqa: BLE001
            raise HomeAssistantError(f"清除缺水提示失败: {err}") from err
