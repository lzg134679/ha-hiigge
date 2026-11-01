"""开关：童锁 / 强力冲刷（全部走 WebSocket）.

两条命令的 id 与字段号都来自 APK 里的
`PetDrinkingFountainID` 与 `PetDrinkingFountain` 的 oneof case，
2026-10-30 用真实设备逐条下发并回读状态验证通过。

**为什么没有"出水"开关**：`drainageMode.on` 是出水总使能，关掉会让设备
直接停止出水（宠物断水，TDS 采样与喝水统计也会停滞）。这个动作风险高、
收益低——出水方式已由 `select.出水方式` 表达（持续/间歇/感应），
只读状态仍在 `binary_sensor`/`sensor` 中可见，因此不提供可写开关。

注意 OptionalSwitcher 是枚举：1=ON、2=OFF（**不是 0/1 布尔**）。

实现要点：描述对象必须用 HA 原生的 `SwitchEntityDescription`。
自定义普通 dataclass 会缺少 `entity_registry_enabled_default` 等字段，
实体在注册阶段会被 HA 直接拒绝 —— v0.4.1 的线上故障就出在这里。
"""

from __future__ import annotations

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import HiiggeCoordinator
from .entity import HiiggeEntity
from .ws import cmd_child_lock, cmd_scour_mode

SWITCHES: tuple[SwitchEntityDescription, ...] = (
    SwitchEntityDescription(
        key="child_lock_mode", name="童锁", icon="mdi:lock-outline"
    ),
    SwitchEntityDescription(key="scour_mode", name="强力冲刷", icon="mdi:shimmer"),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    bucket = hass.data[DOMAIN][entry.entry_id]
    if not bucket.get("enable_control", True):
        return
    coordinator: HiiggeCoordinator = bucket["coordinator"]
    async_add_entities(
        HiiggeSwitch(coordinator, dev.device_id, desc)
        for dev in coordinator.data.devices
        for desc in SWITCHES
        # 设备报 NO_FEATURE(0) 时不建实体
        if dev.status.get(desc.key) is not None
    )


class HiiggeSwitch(HiiggeEntity, SwitchEntity):
    entity_description: SwitchEntityDescription

    def __init__(
        self,
        coordinator: HiiggeCoordinator,
        device_id: str,
        description: SwitchEntityDescription,
    ) -> None:
        super().__init__(coordinator, device_id, description.key)
        self.entity_description = description
        self._attr_unique_id = f"{device_id}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        value = self.status_value(self.entity_description.key)
        return None if value is None else bool(value)

    async def _write(self, turn_on: bool) -> None:
        key = self.entity_description.key
        if key == "child_lock_mode":
            command = cmd_child_lock(turn_on)
        elif key == "scour_mode":
            command = cmd_scour_mode(turn_on)
        else:  # pragma: no cover - 描述表里没有第三条
            return

        # OptionalSwitcher 枚举：1=ON、2=OFF，期望值两处都要登记
        expect = {key: turn_on, f"{key}_raw": 1 if turn_on else 2}
        try:
            await self.coordinator.async_apply_command(command, expect)
        except Exception as err:  # noqa: BLE001
            raise HomeAssistantError(
                f"切换「{self.entity_description.name}」失败: {err}"
            ) from err

    async def async_turn_on(self, **kwargs) -> None:
        await self._write(True)

    async def async_turn_off(self, **kwargs) -> None:
        await self._write(False)
