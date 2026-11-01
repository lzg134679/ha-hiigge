"""选择实体：出水方式 / 出水档位 / 感应灵敏度（写操作，走 WebSocket）.

三条命令都在 ws.py 里实测通过（id=5/17/19），这里只负责把云端状态
映射成可选项，并在用户选择后下发命令。

注意：出水方式与"出水"开关共享同一条 drainageMode 命令
（`on` 字段），切换模式时按 App 的行为带 `on=1`。
"""

from __future__ import annotations

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import HiiggeCoordinator
from .entity import HiiggeEntity
from .proto import GEAR_LABELS, MODE_LABELS, SENSITIVITY_LABELS
from .ws import cmd_drainage_gear, cmd_drainage_mode, cmd_pet_color

# 标签 → 协议原始值（选项文案直接用 proto 里的中文标签，避免两处维护）
MODE_VALUES = {label: value for value, label in MODE_LABELS.items()}
GEAR_VALUES = {label: value for value, label in GEAR_LABELS.items()}
SENSITIVITY_VALUES = {label: value for value, label in SENSITIVITY_LABELS.items()}

# 间歇出水间隔：App 里是固定档位选择，不是任意数字
WAIT_CHOICES = (15, 30, 45, 60, 75, 90, 105, 120)
WAIT_VALUES = {f"{minutes} 分钟": minutes for minutes in WAIT_CHOICES}

SELECTS: tuple[SelectEntityDescription, ...] = (
    SelectEntityDescription(
        key="drainage_mode",
        name="出水方式",
        icon="mdi:water-sync",
        options=list(MODE_VALUES),
    ),
    SelectEntityDescription(
        key="gear_level",
        name="出水档位",
        icon="mdi:gauge",
        options=list(GEAR_VALUES),
    ),
    SelectEntityDescription(
        key="pet_sensitivity",
        name="感应灵敏度",
        icon="mdi:motion-sensor",
        options=list(SENSITIVITY_VALUES),
    ),
    SelectEntityDescription(
        key="intermittent_wait_min",
        name="间歇间隔",
        icon="mdi:timer-sand",
        options=list(WAIT_VALUES),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    # 这里必须取 bucket 里的 coordinator，不能把整个 bucket 当 coordinator 用。
    bucket = hass.data[DOMAIN][entry.entry_id]
    if not bucket.get("enable_control", True):
        return
    coordinator: HiiggeCoordinator = bucket["coordinator"]
    async_add_entities(
        HiiggeSelect(coordinator, dev.device_id, desc)
        for dev in coordinator.data.devices
        for desc in SELECTS
    )


class HiiggeSelect(HiiggeEntity, SelectEntity):
    entity_description: SelectEntityDescription

    def __init__(
        self,
        coordinator: HiiggeCoordinator,
        device_id: str,
        description: SelectEntityDescription,
    ) -> None:
        super().__init__(coordinator, device_id, description.key)
        self.entity_description = description
        self._attr_unique_id = f"{device_id}_{description.key}"

    @property
    def current_option(self) -> str | None:
        value = self.status_value(self.entity_description.key)
        if value is None:
            return None
        if self.entity_description.key == "intermittent_wait_min":
            # 设备回的是分钟数（int），选项是"45 分钟"这类文案
            try:
                text = f"{int(value)} 分钟"
            except (TypeError, ValueError):
                return None
            return text if text in self.entity_description.options else None
        text = str(value)
        # 云端出现未知枚举值（如"未知(4)"）时不假装是某个合法选项
        return text if text in self.entity_description.options else None

    async def async_select_option(self, option: str) -> None:
        key = self.entity_description.key
        if key == "drainage_mode":
            mode = MODE_VALUES[option]
            wait_min = int(self.status_value("intermittent_wait_min") or 45)
            # 与 App 一致：切换出水方式会带 on=1（即"按新模式开始出水"）。
            # 本集成不提供单独关断出水的开关，避免误触导致宠物断水。
            command = cmd_drainage_mode(mode, wait_min, on=1)
            expect = {
                "drainage_mode": option,
                "drainage_mode_raw": mode,
                "drainage_on": True,
            }
        elif key == "gear_level":
            level = GEAR_VALUES[option]
            command = cmd_drainage_gear(level)
            expect = {"gear_level": option, "gear_level_raw": level}
        elif key == "pet_sensitivity":
            color = SENSITIVITY_VALUES[option]
            command = cmd_pet_color(color)
            expect = {"pet_sensitivity": option, "pet_color": color}
        elif key == "intermittent_wait_min":
            # 间隔不是独立命令，而是出水方式命令的 wait 字段：
            # 必须带上当前模式和出水状态，否则会把模式一起改掉
            wait_min = WAIT_VALUES[option]
            mode = int(self.status_value("drainage_mode_raw") or 1)
            on = 1 if self.status_value("drainage_on") in (None, True, 1) else 0
            command = cmd_drainage_mode(mode, wait_min, on=on)
            expect = {"intermittent_wait_min": wait_min}
        else:  # pragma: no cover - 描述表里没有第五条
            return

        try:
            # 带期望值下发：设备回读前界面不会先跳回旧值
            await self.coordinator.async_apply_command(command, expect)
        except Exception as err:  # noqa: BLE001
            raise HomeAssistantError(f"下发「{self.entity_description.name}」失败: {err}") from err
