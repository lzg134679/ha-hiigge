from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "hiigge"

CONF_ACCOUNT = "account"
CONF_PASSWORD = "password"
# 登录用的密码摘要 md5(明文 + SECRET)：不可逆，可重复换 token，用于免密重登
CONF_PASSWORD_HASH = "password_hash"
CONF_BASE_URL = "base_url"
CONF_TOKEN = "token"
CONF_UUID = "device_uuid"
CONF_CHANNEL = "channel"
CONF_SMART_TYPE = "smart_type"
CONF_DEVICE_ID = "device_id"
# 设备所属家庭：喝水统计等接口按家庭维度查询，需要 homeId
CONF_HOME_ID = "home_id"
CONF_ENABLE_CONTROL = "enable_control"
CONF_SCAN_INTERVAL = "scan_interval"

# 短信验证码登录
CONF_SMS_CODE = "sms_code"

DEFAULT_SCAN_INTERVAL = 60
# 控制实体（开关/选择/数字/按钮）默认创建；协议已实测，走 WebSocket 下发
DEFAULT_ENABLE_CONTROL = True

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
]
