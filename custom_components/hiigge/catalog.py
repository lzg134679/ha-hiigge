"""设备品类注册表（smartType）.

`smartType` 是 Hiigge smart-packet 协议层的**设备品类编号**，只在两个接口的
请求体里出现：

    /hiigge/device/api/getHiiggeDeviceStatus      读状态（返回 protobuf）
    /hiigge/device/api/clearWaterVolumeLowStatus  解除「水量低」

它和另外两套编号互不相干，注意别混：

    deviceType = 74   登录/发码签名里的客户端类型（常量，见 api.py 文档串）
    type       = 78   设备档案里的硬件型号编号（PI3501）
    smartType  = 49   协议品类（PET_DRINKING_FOUNTAIN，= SmartPacket.field1）

为什么不在配置表单里让用户填
----------------------------
品类由硬件型号唯一决定，用户无从判断对错；而填错**不会报错**，只会让
服务端返回的 protobuf 按错误的字段表解析 —— 表现为「实体全空」这类静默失败，
排查成本很高。因此改为在下面登记，配置流程按设备档案自动解析。

新增一个品类（例如将来支持喂食器）
----------------------------------
1. 在 `SUPPORTED_PROFILES` 里加一条 `DeviceProfile`；
2. 把该品类已知的硬件型号编号写进 `model_types`；
3. 若它有独立的 protobuf 解码器，把 `decoder` 指过去；暂时没有就留 `None`
   —— 该品类的状态实体会是空值，但不会崩、不会污染其他品类。

配置流程、`__init__.py`、`coordinator.py` 都不需要改，用户也不需要填任何东西。

解析顺序（`resolve_smart_type`）
--------------------------------
1. 服务端若直接给出 `smartType` 字段，以它为准（最可靠）。声明了但未登记则直接
   返回 `None`——服务端说「这是别的品类」，就不能再按饮水机去解析；
2. 否则用硬件型号 `type` 查 `model_types` 反查；
3. 都没命中时，若仅登记了 1 个品类则按该品类兜底（记 WARNING），
   登记了多个品类则返回 `None`，由调用方明确报错而不是猜。

`None` 在配置流程里的表现：中止配置并提示提交 issue 补充型号登记，
而不是建出一个「看起来能跑、状态全错」的条目。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from .proto import decode_status

_LOGGER = logging.getLogger(__name__)

# 品类编号常量（与 SmartPacket.field1 一致）
SMART_TYPE_FOUNTAIN = 49


@dataclass(frozen=True)
class DeviceProfile:
    """一个品类的完整登记信息."""

    smart_type: int
    name: str
    # 该品类下的硬件型号编号（设备档案里的 type 字段）
    model_types: tuple[int, ...] = ()
    # protobuf 状态解码器；None 表示尚未适配，状态按空处理
    decoder: Callable[[str], dict[str, Any]] | None = None


SUPPORTED_PROFILES: dict[int, DeviceProfile] = {
    SMART_TYPE_FOUNTAIN: DeviceProfile(
        smart_type=SMART_TYPE_FOUNTAIN,
        name="宠物饮水机",
        model_types=(78,),  # PI3501
        decoder=decode_status,
    ),
}

DEFAULT_SMART_TYPE = SMART_TYPE_FOUNTAIN

_MODEL_TYPE_TO_SMART_TYPE: dict[int, int] = {
    model_type: profile.smart_type
    for profile in SUPPORTED_PROFILES.values()
    for model_type in profile.model_types
}


def normalize_smart_type(value: Any) -> int | None:
    """把配置里存的原始值收敛成受支持的品类编号；不可用时返回 None.

    用于兼容早期条目：那时 smartType 由用户在表单里手填，可能是空、0 或乱填。
    """
    try:
        smart_type = int(value)
    except (TypeError, ValueError):
        return None
    return smart_type if smart_type in SUPPORTED_PROFILES else None


def resolve_smart_type(device: dict[str, Any]) -> int | None:
    """按设备档案推断品类编号；无法确定时返回 None."""
    # 1) 服务端直接声明：以它为准。声明了但没登记 → 明确返回 None，不做猜测，
    #    否则会拿饮水机的字段表去解析别的品类的数据。
    if "smartType" in device or "smart_type" in device:
        raw = device.get("smartType", device.get("smart_type"))
        declared = normalize_smart_type(raw)
        if declared is None:
            _LOGGER.warning("设备声明的 smartType=%r 未登记，无法解析其状态", raw)
        return declared

    # 2) 用硬件型号反查
    raw_model = device.get("type") or device.get("deviceType")
    try:
        model_type = int(raw_model)
    except (TypeError, ValueError):
        model_type = 0
    if model_type in _MODEL_TYPE_TO_SMART_TYPE:
        return _MODEL_TYPE_TO_SMART_TYPE[model_type]

    # 3) 兜底：只登记了一个品类时不存在歧义
    if len(SUPPORTED_PROFILES) == 1:
        only = next(iter(SUPPORTED_PROFILES))
        _LOGGER.warning(
            "硬件型号 type=%s 未登记，暂按唯一已支持品类 %s 处理；如设备工作异常，"
            "请把型号补进 catalog.SUPPORTED_PROFILES",
            model_type,
            only,
        )
        return only

    _LOGGER.error(
        "无法确定设备品类：type=%s 未登记，且已支持 %d 个品类",
        model_type,
        len(SUPPORTED_PROFILES),
    )
    return None


def decode_status_for(smart_type: int, hex_str: str) -> dict[str, Any]:
    """按品类选择解码器；未适配解码器的品类返回空字典（不抛异常）."""
    profile = SUPPORTED_PROFILES.get(smart_type)
    if profile is None:
        _LOGGER.debug("smartType=%s 未登记，跳过状态解析", smart_type)
        return {}
    if profile.decoder is None:
        _LOGGER.debug("品类「%s」尚未适配解码器，跳过状态解析", profile.name)
        return {}
    return profile.decoder(hex_str)


def describe_smart_type(smart_type: int) -> str:
    """给日志/报错用的可读描述."""
    profile = SUPPORTED_PROFILES.get(smart_type)
    return profile.name if profile else f"未知品类({smart_type})"
