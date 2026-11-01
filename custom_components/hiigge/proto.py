"""饮水机状态 Protobuf 解码器.

`getHiiggeDeviceStatus` 返回的是 `dataHexStr`（十六进制 protobuf），
不是 JSON。字段表是从 APK 里 `PetDrinkingFountainStatus` 生成类的
`*_FIELD_NUMBER` 常量逐条读出来的（见逆向报告 §7），不是猜的。

顶层 `PetDrinkingFountainStatus`：

    1  drainage_mode            DrainageMode
    2  battery                  SystemProtos.DeviceStatus
                                 └ 1 Battery{1 capacity, 2 charge_status,
                                            3 low_battery_status, 4 low_voltage_warning}
    3  quiet_mode               SystemProtos.QuietMode
    4  filter_element           FilterElement
    5  water_quality            WaterQuality
    6  water_quality_abnormal   bool
    7  water_volume_low         bool
    8  filter_expired           bool
    9  quiet_mode_enabled       bool
    10 scour_mode               OptionalSwitcher
    11 child_lock_mode          OptionalSwitcher
    12 long_endurance_mode      OptionalSwitcher
    13 drainage_gear            DrainageGear
    15 water_pump_block         bool
    16 pet_color                PetColorConfig
    17 led_quiet                LedQuietMode
    18 led_quiet_enabled        bool
    19 uv_enabled               bool
    20 water_inflow             bool
    255 timestamp               int64 (秒)
"""

from __future__ import annotations

from typing import Any

# DrainageMode.Mode
# 感应灵敏度：对应 App 里「适用于浅色/深色宠物」
SENSITIVITY_LABELS = {1: "浅色宠物（标准）", 2: "深色宠物（增强）"}

# OptionalSwitcher 枚举（com.mai70.smart.protobuf.CommonProtos$OptionalSwitcher）：
#   0 = NO_FEATURE（本机型无此功能）、1 = ON、2 = OFF
# 注意 OFF 不是 0，直接 bool(2) 会永远为真，必须按枚举映射。
SWITCHER_VALUES = {1: True, 2: False}

# Battery.ChargeStatus（SystemProtos$DeviceStatus$Battery$ChargeStatus）：
# 常量名与数值取自 APK 中该枚举的 <clinit>：
#   0 = UNKNOWN、1 = CHARGING、2 = NOT_CHARGING、3 = FULL
CHARGE_STATUS_LABELS = {
    0: "未知",
    1: "充电中",
    2: "未充电",
    3: "已充满",
}
# 「是否充电中」只看 CHARGING：FULL 表示已充满并转由外部供电，与 HA 里
# battery_charging 二值传感器的语义一致（充满即非充电中）。
CHARGE_STATUS_VALUES = {1: True, 2: False, 3: False}
# 「是否连接电源」：CHARGING 与 FULL 都意味着电源线接着（FULL = 接着且已充满），
# 只有 NOT_CHARGING 才表示没插电。用于判断设备是否处于供电状态。
POWER_CONNECTED_VALUES = {1: True, 2: False, 3: True}

MODE_LABELS = {
    1: "间歇出水",
    2: "感应出水",
    3: "持续出水",
}
# DrainageGear.Level
GEAR_LABELS = {
    1: "低",
    2: "中",
    3: "高",
}


def _varint(buf: bytes, idx: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = buf[idx]
        idx += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, idx


def parse_message(buf: bytes) -> dict[int, list[Any]]:
    """把一段 protobuf 解成 {字段号: [值, ...]}；wiretype 2 的值是 bytes."""
    out: dict[int, list[Any]] = {}
    idx = 0
    size = len(buf)
    while idx < size:
        key, idx = _varint(buf, idx)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, idx = _varint(buf, idx)
        elif wire == 2:
            length, idx = _varint(buf, idx)
            value = buf[idx : idx + length]
            idx += length
        elif wire == 5:
            value = int.from_bytes(buf[idx : idx + 4], "little")
            idx += 4
        elif wire == 1:
            value = int.from_bytes(buf[idx : idx + 8], "little")
            idx += 8
        else:  # 未知 wiretype，放弃剩余部分
            break
        out.setdefault(field, []).append(value)
    return out


def _first(fields: dict[int, list[Any]], num: int, default: Any = None) -> Any:
    values = fields.get(num)
    return values[0] if values else default


def _sub(fields: dict[int, list[Any]], num: int) -> dict[int, list[Any]]:
    raw = _first(fields, num)
    return parse_message(raw) if isinstance(raw, (bytes, bytearray)) else {}


def _bool(fields: dict[int, list[Any]], num: int) -> bool | None:
    value = _first(fields, num)
    return None if value is None else bool(value)


def decode_status(hex_str: str) -> dict[str, Any]:
    """解出语义化字典。缺失字段一律不出现。"""
    try:
        top = parse_message(bytes.fromhex(hex_str))
    except (ValueError, IndexError):
        return {}

    data: dict[str, Any] = {}

    # 1 出水模式
    dm = _sub(top, 1)
    if dm:
        mode = _first(dm, 2)
        data["drainage_mode_raw"] = mode
        data["drainage_mode"] = MODE_LABELS.get(mode, f"未知({mode})")
        data["drainage_on"] = _bool(dm, 1)
        wait = _first(dm, 3)
        if wait is not None:
            data["intermittent_wait_min"] = wait

    # 2 电池（Battery 在 field 1 里）
    dev_status = _sub(top, 2)
    if dev_status:
        battery = _sub(dev_status, 1)
        if battery:
            cap = _first(battery, 1)
            if cap is not None:
                data["battery_capacity"] = cap
            cs = _first(battery, 2)
            if cs is not None:
                data["battery_charge_status"] = cs
                # 0 = UNKNOWN 时只留原始值，不产出标签/充电实体，避免建出永久未知的实体
                if cs:
                    data["battery_charge_status_label"] = CHARGE_STATUS_LABELS.get(
                        cs, f"未知({cs})"
                    )
                charging = CHARGE_STATUS_VALUES.get(cs)
                if charging is not None:
                    data["battery_charging"] = charging
                powered = POWER_CONNECTED_VALUES.get(cs)
                if powered is not None:
                    data["power_connected"] = powered
        charging = _sub(dev_status, 2)
        if charging:
            volt = _first(charging, 4)
            if volt is not None:
                data["battery_voltage"] = volt

    # 3 夜间免打扰时段
    quiet = _sub(top, 3)
    if quiet:
        data["quiet_enable"] = _bool(quiet, 1)
        data["quiet_timed_enable"] = _bool(quiet, 2)
        start = _first(quiet, 3)
        end = _first(quiet, 4)
        if start is not None:
            data["quiet_start"] = _seconds_to_hhmm(start)
        if end is not None:
            data["quiet_end"] = _seconds_to_hhmm(end)

    # 4 滤芯
    flt = _sub(top, 4)
    if flt:
        total = _first(flt, 1)
        daily = _first(flt, 3)
        used = _first(flt, 4)
        start_ts = _first(flt, 2)
        if total is not None:
            data["filter_total_days"] = total
        if daily is not None:
            data["filter_daily_usage"] = daily
        if used is not None:
            data["filter_total_usage"] = used
        if start_ts:
            data["filter_start_ts"] = start_ts
        if total is not None and daily:
            consumed_days = (used or 0) / daily if daily else 0
            remain = max(0.0, float(total) - consumed_days)
            data["filter_remain_days"] = round(remain, 1)
            data["filter_remain_percent"] = round(min(100.0, remain / total * 100), 1)

    # 5 水质
    wq = _sub(top, 5)
    if wq:
        tds = _first(wq, 3)
        if tds is not None:
            data["tds"] = tds

    # 6..20 布尔/枚举
    for num, key in (
        (6, "water_quality_abnormal"),
        (7, "water_volume_low"),
        (8, "filter_expired"),
        (9, "quiet_mode_enabled"),
        (15, "water_pump_block"),
        (18, "led_quiet_enabled"),
        (19, "uv_enabled"),
        (20, "water_inflow"),
    ):
        value = _bool(top, num)
        if value is not None:
            data[key] = value

    for num, key in ((10, "scour_mode"), (11, "child_lock_mode"), (12, "long_endurance_mode")):
        value = _first(top, num)
        if value is not None:
            # 0 = NO_FEATURE → 无此功能，不产出键（实体不会创建）
            data[f"{key}_raw"] = value
            mapped = SWITCHER_VALUES.get(value)
            if mapped is not None:
                data[key] = mapped

    gear = _sub(top, 13)
    if gear:
        level = _first(gear, 1)
        data["gear_level_raw"] = level
        data["gear_level"] = GEAR_LABELS.get(level, f"未知({level})")

    color = _sub(top, 16)
    if color:
        level = _first(color, 1)
        data["pet_color"] = level
        data["pet_sensitivity"] = SENSITIVITY_LABELS.get(level, f"未知({level})")

    ts = _first(top, 255)
    if ts:
        data["device_ts"] = ts

    return data


def _seconds_to_hhmm(seconds: int) -> str:
    try:
        seconds = int(seconds) % 86400
    except (TypeError, ValueError):
        return str(seconds)
    return f"{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}"
