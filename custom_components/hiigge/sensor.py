"""传感器：TDS、电量、滤芯、出水模式/档位."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import HiiggeCoordinator
from .entity import HiiggeEntity


@dataclass(frozen=True, kw_only=True)
class HiiggeSensorDescription(SensorEntityDescription):
    field: str


def _num(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


SENSORS: tuple[HiiggeSensorDescription, ...] = (
    HiiggeSensorDescription(
        key="tds", field="tds", name="水质 TDS",
        native_unit_of_measurement="ppm", state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:water-percent",
    ),
    HiiggeSensorDescription(
        key="battery", field="battery_capacity", name="电量",
        native_unit_of_measurement=PERCENTAGE, device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    HiiggeSensorDescription(
        key="battery_voltage", field="battery_voltage", name="电池电压",
        native_unit_of_measurement="mV", state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC, icon="mdi:battery-heart-variant",
    ),
    # charge_status 枚举：充电中 / 未充电 / 已充满（二值「充电中」见 binary_sensor.py）
    HiiggeSensorDescription(
        key="charge_status", field="battery_charge_status_label", name="充电状态",
        entity_category=EntityCategory.DIAGNOSTIC, icon="mdi:battery-charging-outline",
    ),
    HiiggeSensorDescription(
        key="filter_days", field="filter_remain_days", name="滤芯剩余天数",
        native_unit_of_measurement=UnitOfTime.DAYS, state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:air-filter",
    ),
    HiiggeSensorDescription(
        key="filter_percent", field="filter_remain_percent", name="滤芯剩余寿命",
        native_unit_of_measurement=PERCENTAGE, state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:air-filter",
    ),
    # 以下四条与可写的 select/number 实体重复，仅作为只读快照保留在诊断分类里，
    # 避免与同名控制实体在界面上并列造成混淆（自动化仍可引用）。
    HiiggeSensorDescription(
        key="mode", field="drainage_mode", name="出水模式（只读）", icon="mdi:water-pump",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    HiiggeSensorDescription(
        key="gear", field="gear_level", name="出水档位（只读）", icon="mdi:speedometer",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    HiiggeSensorDescription(
        key="sensitivity",
        field="pet_sensitivity",
        name="感应灵敏度（只读）",
        icon="mdi:motion-sensor",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    HiiggeSensorDescription(
        key="filter_usage",
        field="filter_total_usage",
        name="滤芯净化次数",
        icon="mdi:counter",
        state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    HiiggeSensorDescription(
        key="filter_start",
        field="filter_start_ts",
        name="滤芯重置日期",
        icon="mdi:calendar-check",
        device_class=SensorDeviceClass.TIMESTAMP,
    ),
    HiiggeSensorDescription(
        key="wait", field="intermittent_wait_min", name="间歇间隔（只读）",
        native_unit_of_measurement=UnitOfTime.MINUTES, state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:timer-outline", entity_category=EntityCategory.DIAGNOSTIC,
    ),
    HiiggeSensorDescription(
        key="device_ts", field="device_ts", name="设备上报时间",
        device_class=SensorDeviceClass.TIMESTAMP, entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:clock-outline",
    ),
    HiiggeSensorDescription(
        key="quiet_window", field="quiet_end", name="免打扰结束",
        icon="mdi:weather-night", entity_category=EntityCategory.DIAGNOSTIC,
    ),
    # -- 喝水统计（今日，家庭维度接口 getHomeTodayDrinkData） ---------------
    # 对应 App 首页的「N 次」与详情页的分时折线；数据按「截止当前时刻」统计
    HiiggeSensorDescription(
        key="drink_count", field="drink_count", name="今日喝水次数",
        native_unit_of_measurement="次", state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:cup-water",
    ),
    HiiggeSensorDescription(
        key="drink_duration", field="drink_duration_sec", name="今日喝水时长",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT, icon="mdi:timer-sand",
    ),
    HiiggeSensorDescription(
        key="drink_last", field="drink_last_ts", name="最近喝水时间",
        device_class=SensorDeviceClass.TIMESTAMP, icon="mdi:clock-check-outline",
    ),
    HiiggeSensorDescription(
        key="drink_avg", field="drink_avg_duration_sec", name="平均每次喝水时长",
        native_unit_of_measurement=UnitOfTime.SECONDS,
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC, icon="mdi:timer-outline",
    ),
    HiiggeSensorDescription(
        key="drink_compare", field="drink_compare_avg", name="较日均喝水次数差",
        native_unit_of_measurement="次", state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC, icon="mdi:chart-line",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: HiiggeCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    entities = []
    for dev in coordinator.data.devices:
        for desc in SENSORS:
            # 喝水统计来自独立接口，首轮可能尚未取到；实体仍要建出来，
            # 否则一旦第一次拉取失败，实体就永远不存在了。
            if dev.status.get(desc.field) is None and not desc.key.startswith("drink"):
                continue
            entities.append(HiiggeSensor(coordinator, dev.device_id, desc))
    async_add_entities(entities)


class HiiggeSensor(HiiggeEntity, SensorEntity):
    entity_description: HiiggeSensorDescription

    def __init__(
        self, coordinator: HiiggeCoordinator, device_id: str, description: HiiggeSensorDescription
    ) -> None:
        super().__init__(coordinator, device_id, description.key)
        self.entity_description = description
        self._attr_unique_id = f"{device_id}_{description.key}"

    @property
    def native_value(self) -> Any:
        desc = self.entity_description
        value = self.status_value(desc.field)
        if value is None:
            return None
        if desc.device_class == SensorDeviceClass.TIMESTAMP:
            return _to_datetime(value)
        if desc.native_unit_of_measurement or desc.state_class:
            return _num(value) if not isinstance(value, str) or _num(value) is not None else value
        return value

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """喝水类实体额外带出当天的分时明细，方便做历史/图表."""
        if not self.entity_description.key.startswith("drink"):
            return {}
        hourly = self.status_value("drink_hourly") or []
        return {
            "date": self.status_value("drink_date"),
            "active_hours": self.status_value("drink_active_hours"),
            "last_hour": self.status_value("drink_last_hour"),
            "hourly": [
                {"hour": f"{int(item['hour']):02d}:00", "duration_sec": item.get("duration")}
                for item in hourly
                if isinstance(item, dict) and item.get("hour") is not None
            ],
        }


def _to_datetime(value: Any) -> datetime | None:
    # 喝水统计直接给出 datetime；其余字段是毫秒时间戳
    if isinstance(value, datetime):
        return value
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    if ts > 1e12:
        ts /= 1000.0
    try:
        return datetime.fromtimestamp(ts).astimezone()
    except (OverflowError, OSError, ValueError):
        return None
