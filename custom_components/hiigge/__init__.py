"""Hiigge 宠物设备集成入口."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed

from .api import BASE_CN, DEFAULT_CHANNEL, HiiggeApi, Session
from .catalog import DEFAULT_SMART_TYPE, normalize_smart_type
from .const import (
    CONF_BASE_URL,
    CONF_CHANNEL,
    CONF_DEVICE_ID,
    CONF_ENABLE_CONTROL,
    CONF_HOME_ID,
    CONF_SCAN_INTERVAL,
    CONF_SMART_TYPE,
    CONF_TOKEN,
    CONF_UUID,
    DEFAULT_ENABLE_CONTROL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import HiiggeCoordinator

_LOGGER = logging.getLogger(__name__)


def _session_from_entry(data: dict) -> Session | None:
    """从配置构造会话。签名不需要存——每个请求按当前时间现算。"""
    token = data.get(CONF_TOKEN)
    uid = data.get(CONF_UUID)
    if not (token and uid):
        return None
    return Session(
        token=str(token),
        uuid=str(uid),
        channel=int(data.get(CONF_CHANNEL) or DEFAULT_CHANNEL),
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = {**entry.data, **entry.options}

    device_id = data.get(CONF_DEVICE_ID)
    if not device_id:
        raise ConfigEntryAuthFailed("配置缺少 device_id，请重新配置")

    session = _session_from_entry(data)
    if session is None:
        raise ConfigEntryAuthFailed("配置缺少 token/uuid，请重新登录")

    api = HiiggeApi(data.get(CONF_BASE_URL, BASE_CN), session=session)

    # 品类（smartType）由设备型号决定，正常情况下配置阶段已自动判定并落库。
    # 早期条目可能是用户手填的脏值，这里收敛一次，避免拿错误的字段表解析状态。
    smart_type = normalize_smart_type(data.get(CONF_SMART_TYPE))
    if smart_type is None:
        _LOGGER.warning(
            "配置条目里的 smart_type=%r 不在支持列表，回退默认品类 %s（如需纠正请重新添加集成）",
            data.get(CONF_SMART_TYPE),
            DEFAULT_SMART_TYPE,
        )
        smart_type = DEFAULT_SMART_TYPE

    coordinator = HiiggeCoordinator(
        hass,
        api,
        device_id,
        int(data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)),
        smart_type,
        data.get(CONF_HOME_ID),
    )
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        "api": api,
        "coordinator": coordinator,
        "enable_control": data.get(CONF_ENABLE_CONTROL, DEFAULT_ENABLE_CONTROL),
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        bucket = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        # 收起写后回读任务，避免卸载后仍有一条后台协程在跑
        if bucket and bucket.get("coordinator"):
            bucket["coordinator"].async_cancel_pending()
    return unload_ok
