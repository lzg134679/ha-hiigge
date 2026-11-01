"""配置流程：三种登录方式任选。

流程
----
    user ──┬─ password（手机号 + 密码）── 登录 ─→ 自动发现设备 ─→ 完成
           ├─ sms（手机号 + 验证码）── 发码 ─→ 输入验证码 ─→ 登录 ─→ 完成
           └─ token（自行抓包）────── 填 token + uuid ─→ 完成

验证码链路（2026-10-29 协议探测确认）
------------------------------------
    POST /accountApi/V3/sendUserVerifyCode  {mobile, deviceType, type:2, ...}
    POST /accountApi/V2/userLogin           {mobile, mobileVerifyCode, ...}

两者签名相同：`md5(deviceType + "null" + mobile + ts + SECRET)`，
与密码登录的差别只是**没有密码摘要那一段**。
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .api import (
    BASE_CN,
    BASE_EU,
    BASE_INTL,
    BASE_NA,
    DEFAULT_CHANNEL,
    HiiggeApi,
    HiiggeApiError,
    HiiggeAuthError,
    HiiggeError,
    HiiggeRateLimitError,
    HiiggeVerifyCodeError,
    HiiggeVerifyLockedError,
    Session,
    hash_password,
)
from .catalog import normalize_smart_type, resolve_smart_type
from .const import (
    CONF_ACCOUNT,
    CONF_BASE_URL,
    CONF_CHANNEL,
    CONF_DEVICE_ID,
    CONF_ENABLE_CONTROL,
    CONF_HOME_ID,
    CONF_PASSWORD,
    CONF_PASSWORD_HASH,
    CONF_SCAN_INTERVAL,
    CONF_SMART_TYPE,
    CONF_SMS_CODE,
    CONF_TOKEN,
    CONF_UUID,
    DEFAULT_ENABLE_CONTROL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# 服务器选项：key = 实际请求的 base URL（存储值），value = 下拉框显示文案
# 默认国内服（2026-10-28 实测通过），海外服同协议可达但未逐项验证
SERVER_CHOICES: dict[str, str] = {
    BASE_CN: f"国内服  {BASE_CN}",
    BASE_INTL: f"国际服  {BASE_INTL}",
    BASE_EU: f"欧洲服  {BASE_EU}",
    BASE_NA: f"北美服  {BASE_NA}",
}

# 「重新发送验证码」开关的字段名（不落库，仅用于表单交互）
CONF_RESEND = "resend"


class HiiggeConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 6

    def __init__(self) -> None:
        self._pending: dict[str, Any] = {}
        # 验证码流程跨步骤复用同一个 api 实例：
        # 发码与登录必须携带同一个 uuid，服务端才会把验证码和会话对上
        self._sms_api: HiiggeApi | None = None
        # 仅 reauth 使用：从已有条目进入时复用其服务器地址。
        # 注意不能命名为 `_reauth_entry_id`：HA 基类 ConfigFlow 已把它定义为只读
        # property，在 __init__ 中赋值会抛 AttributeError，导致配置流程 500。
        self._hiigge_reauth_entry_id: str | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        return self.async_show_menu(
            step_id="user",
            menu_options=["password", "sms", "token"],
        )

    # -- 账号密码 ----------------------------------------------------------
    async def async_step_password(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            base = user_input.get(CONF_BASE_URL, BASE_CN)
            mobile = user_input[CONF_ACCOUNT].strip()
            password = user_input[CONF_PASSWORD]
            api = HiiggeApi(base)
            try:
                await api.login(mobile, password)
                devices = await api.all_devices()
            except HiiggeAuthError as err:
                _LOGGER.warning("登录失败: %s", err)
                errors["base"] = "invalid_auth"
            except HiiggeApiError as err:
                # 服务端明确拒绝（与网络无关），别误导成"网络异常"
                _LOGGER.warning("登录被服务端拒绝: %s", err)
                errors["base"] = "api_rejected"
            except HiiggeError as err:
                _LOGGER.warning("登录异常: %s", err)
                errors["base"] = "cannot_connect"
            else:
                if not devices:
                    errors["base"] = "no_devices"
                elif len(devices) == 1:
                    return await self._finish(
                        api.session,
                        devices[0],
                        base,
                        mobile,
                        pwd_hash=hash_password(password),
                    )
                else:
                    self._pending = {
                        "session": api.session,
                        "devices": devices,
                        "base": base,
                        "account": mobile,
                        "pwd_hash": hash_password(password),
                    }
                    return await self.async_step_pick_device()

        return self.async_show_form(
            step_id="password",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ACCOUNT): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Optional(CONF_BASE_URL, default=BASE_CN): vol.In(SERVER_CHOICES),
                }
            ),
            errors=errors,
            description_placeholders={
                "hint": (
                    "同一账号只能在一处保持登录：集成登录会把手机 App 挤下线，"
                    "反之亦然。建议注册小号并加入大号家庭，集成用小号登录。"
                    "密码不会以明文保存，只保存登录用的摘要，便于 token 失效后一键重登。"
                )
            },
        )

    # -- 手机号 + 验证码 ---------------------------------------------------
    async def async_step_sms(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """第 1 步：填手机号并请求短信验证码。"""
        errors: dict[str, str] = {}
        if user_input is not None:
            base = user_input.get(CONF_BASE_URL, BASE_CN)
            mobile = str(user_input[CONF_ACCOUNT]).strip()
            api = HiiggeApi(base)
            try:
                await api.send_verify_code(mobile)
            except HiiggeRateLimitError as err:
                _LOGGER.warning("验证码发送被限频: %s", err)
                errors["base"] = "code_rate_limited"
            except HiiggeError as err:
                _LOGGER.warning("验证码发送失败: %s", err)
                errors["base"] = "cannot_connect"
            else:
                self._sms_api = api
                self._pending = {
                    "base": base,
                    "account": mobile,
                    "resent": False,
                }
                return await self.async_step_sms_code()

        return self.async_show_form(
            step_id="sms",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ACCOUNT): str,
                    vol.Optional(CONF_BASE_URL, default=BASE_CN): vol.In(SERVER_CHOICES),
                }
            ),
            errors=errors,
            description_placeholders={
                "hint": "填 App 登录用的手机号，提交后会下发短信验证码。"
            },
        )

    async def async_step_sms_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """第 2 步：输入收到的 6 位验证码完成登录。"""
        errors: dict[str, str] = {}
        api = self._sms_api
        pending = self._pending
        if api is None or not pending:
            # 流程被打断（例如刷新了页面），回到第一步
            return await self.async_step_sms()

        mobile = pending["account"]
        base = pending["base"]

        if user_input is not None:
            if user_input.get(CONF_RESEND):
                # 用户要求重新下发验证码：不消耗提交的验证码，停留在当前步骤
                try:
                    await api.send_verify_code(mobile)
                except HiiggeRateLimitError as err:
                    _LOGGER.warning("重新发送验证码被限频: %s", err)
                    errors["base"] = "code_rate_limited"
                except HiiggeError as err:
                    _LOGGER.warning("重新发送验证码失败: %s", err)
                    errors["base"] = "cannot_connect"
                else:
                    pending["resent"] = True
                return self._show_sms_code_form(errors)

            code = str(user_input.get(CONF_SMS_CODE, "")).strip()
            try:
                await api.login_sms(mobile, code)
                devices = await api.all_devices()
            except HiiggeVerifyCodeError as err:
                _LOGGER.warning("验证码无效: %s", err)
                errors["base"] = "invalid_code"
            except HiiggeVerifyLockedError as err:
                _LOGGER.warning("验证码连续错误已达上限: %s", err)
                errors["base"] = "code_locked"
            except HiiggeRateLimitError as err:
                _LOGGER.warning("验证码校验被限频: %s", err)
                errors["base"] = "code_rate_limited"
            except HiiggeAuthError as err:
                _LOGGER.warning("验证码登录失败: %s", err)
                errors["base"] = "invalid_auth"
            except HiiggeError as err:
                _LOGGER.warning("验证码登录异常: %s", err)
                errors["base"] = "cannot_connect"
            else:
                if not devices:
                    errors["base"] = "no_devices"
                elif len(devices) == 1:
                    return await self._finish(api.session, devices[0], base, mobile)
                else:
                    self._pending = {
                        "session": api.session,
                        "devices": devices,
                        "base": base,
                        "account": mobile,
                    }
                    return await self.async_step_pick_device()

        return self._show_sms_code_form(errors)

    def _show_sms_code_form(self, errors: dict[str, str]) -> FlowResult:
        pending = self._pending
        mobile = pending.get("account", "")
        if pending.get("resent"):
            hint = f"验证码已重新发送至 {mobile}，请查收短信。"
        else:
            hint = f"验证码已发送至 {mobile}，10 分钟内有效。"
        return self.async_show_form(
            step_id="sms_code",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SMS_CODE): str,
                    vol.Optional(CONF_RESEND, default=False): bool,
                }
            ),
            errors=errors,
            description_placeholders={"hint": hint},
        )

    # -- 选择设备 ----------------------------------------------------------
    async def async_step_pick_device(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        devices = self._pending["devices"]
        choices = {
            str(d.get("deviceId")): f"{d.get('deviceNickName') or d.get('deviceId')}"
            for d in devices
            if d.get("deviceId")
        }
        if user_input is not None:
            device_id = user_input[CONF_DEVICE_ID]
            device = next(d for d in devices if d.get("deviceId") == device_id)
            return await self._finish(
                self._pending["session"],
                device,
                self._pending["base"],
                self._pending["account"],
                pwd_hash=self._pending.get("pwd_hash"),
            )
        return self.async_show_form(
            step_id="pick_device",
            data_schema=vol.Schema({vol.Required(CONF_DEVICE_ID): vol.In(choices)}),
        )

    def _resolve_smart_type(self, device: dict[str, Any]) -> int | None:
        """确定设备品类（smartType）。

        - 重新认证：沿用原条目里已经验证过的值，避免同一台设备被重新判定；
        - 新配置：按设备档案自动解析（见 `catalog.resolve_smart_type`）。
        """
        if self._hiigge_reauth_entry_id:
            entry = self.hass.config_entries.async_get_entry(
                self._hiigge_reauth_entry_id
            )
            if entry is not None:
                stored = normalize_smart_type(entry.data.get(CONF_SMART_TYPE))
                if stored is not None:
                    return stored
        return resolve_smart_type(device)

    async def _finish(
        self,
        session: Session,
        device: dict[str, Any],
        base: str,
        account: str,
        pwd_hash: str | None = None,
    ) -> FlowResult:
        device_id = str(device.get("deviceId"))
        smart_type = self._resolve_smart_type(device)
        if smart_type is None:
            # 品类不在注册表里：宁可明确报错，也不要拿错误的字段表去解析状态
            return self.async_abort(
                reason="unsupported_device",
                description_placeholders={
                    "model": str(
                        device.get("type") or device.get("deviceType") or "未知"
                    )
                },
            )
        if self._hiigge_reauth_entry_id:
            # 从「重新认证」进入：更新原条目而不是新建。
            # 注意不能先做 _async_abort_entries_match —— 那会匹配到自己这条而误判「已配置」。
            entry = self.hass.config_entries.async_get_entry(
                self._hiigge_reauth_entry_id
            )
            if entry is not None:
                data = {
                    **entry.data,
                    CONF_ACCOUNT: account,
                    CONF_TOKEN: session.token,
                    CONF_UUID: session.uuid,
                    CONF_CHANNEL: session.channel or DEFAULT_CHANNEL,
                }
                if pwd_hash:
                    # 换过密码或首次存下摘要时更新它；验证码登录则保留原值
                    data[CONF_PASSWORD_HASH] = pwd_hash
                return self.async_update_reload_and_abort(entry, data=data)
        self._async_abort_entries_match({CONF_DEVICE_ID: device_id})
        data = {
            CONF_ACCOUNT: account,
            CONF_BASE_URL: base,
            CONF_DEVICE_ID: device_id,
            # 喝水统计按家庭维度查询，配置阶段顺手存下来
            CONF_HOME_ID: device.get("_homeId"),
            CONF_TOKEN: session.token,
            CONF_UUID: session.uuid,
            CONF_CHANNEL: session.channel or DEFAULT_CHANNEL,
            CONF_SMART_TYPE: smart_type,
        }
        if pwd_hash:
            data[CONF_PASSWORD_HASH] = pwd_hash
        return self.async_create_entry(
            title=str(device.get("deviceNickName") or device_id),
            data=data,
            options={CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL},
        )

    # -- 手动 token（自行抓包，不想交账号时用） ----------------------------
    async def async_step_token(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            base = user_input.get(CONF_BASE_URL, BASE_CN)
            try:
                session = Session.from_capture(
                    {
                        "token": user_input[CONF_TOKEN],
                        "uuid": user_input.get(CONF_UUID, ""),
                    }
                )
            except ValueError:
                errors["base"] = "bad_token"
            else:
                api = HiiggeApi(base, session=session)
                try:
                    devices = await api.all_devices()
                except HiiggeError as err:
                    _LOGGER.warning("token 校验失败: %s", err)
                    errors["base"] = "invalid_auth"
                else:
                    if not devices:
                        errors["base"] = "no_devices"
                    elif len(devices) == 1:
                        return await self._finish(
                            session, devices[0], base, "token"
                        )
                    else:
                        self._pending = {
                            "session": session,
                            "devices": devices,
                            "base": base,
                            "account": "token",
                        }
                        return await self.async_step_pick_device()

        return self.async_show_form(
            step_id="token",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_TOKEN): str,
                    vol.Required(CONF_UUID): str,
                    vol.Optional(CONF_BASE_URL, default=BASE_CN): vol.In(SERVER_CHOICES),
                }
            ),
            errors=errors,
            description_placeholders={
                "hint": "从抓包记录里任取一条请求的 token 与 uuid。"
            },
        )

    # -- reauth ------------------------------------------------------------
    def _reauth_entry(self):
        """取「重新认证」对应的配置条目（兼容新旧 HA）.

        HA 2025.1 起 reauth 入口不再传 entry_data，改用 `_get_reauth_entry()`；
        更早的版本靠 `context["entry_id"]`。两条路都试，取不到就返回 None，
        由调用方明确 abort —— 绝不能像以前那样直接 `entry_data.get()` 崩成 500。
        """
        getter = getattr(self, "_get_reauth_entry", None)
        if callable(getter):
            try:
                entry = getter()
            except Exception:  # noqa: BLE001 - 老版本没有该实现时会抛
                entry = None
            if entry is not None:
                return entry
        entry_id = self.context.get("entry_id")
        if not entry_id:
            return None
        return self.hass.config_entries.async_get_entry(entry_id)

    async def async_step_reauth(
        self, entry_data: dict[str, Any] | None = None
    ) -> FlowResult:
        entry = self._reauth_entry()
        if entry is None:
            # 拿不到原条目（flow 上下文丢失）时明确中止，而不是抛异常
            return self.async_abort(reason="reauth_failed")
        self._hiigge_reauth_entry_id = entry.entry_id
        account = (
            (entry_data or {}).get(CONF_ACCOUNT)
            or entry.data.get(CONF_ACCOUNT, "")
        )
        options = ["reauth_confirm", "reauth_sms"]
        if entry.data.get(CONF_PASSWORD_HASH):
            # 存过密码摘要就把「免密重登」放在第一位，省去每次输密码
            options.insert(0, "reauth_saved")
        return self.async_show_menu(
            step_id="reauth",
            menu_options=options,
            description_placeholders={"account": str(account)},
        )

    async def async_step_reauth_saved(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """用已保存的密码摘要直接换新 token（无需输入密码）."""
        entry = self._reauth_entry()
        if entry is None:
            return self.async_abort(reason="reauth_failed")
        self._hiigge_reauth_entry_id = entry.entry_id

        account = str(entry.data.get(CONF_ACCOUNT, "")).strip()
        pwd_hash = entry.data.get(CONF_PASSWORD_HASH)
        if not (account and pwd_hash):
            return self.async_abort(reason="reauth_no_saved_credential")

        base = entry.data.get(CONF_BASE_URL, BASE_CN)
        api = HiiggeApi(base)
        try:
            await api.login_with_hash(account, pwd_hash)
        except HiiggeAuthError as err:
            # 摘要失效（改过密码）或被服务端拒绝：让用户改走密码 / 验证码
            _LOGGER.warning("凭已保存凭据重新登录失败: %s", err)
            return self.async_abort(reason="reauth_saved_invalid")
        except HiiggeApiError as err:
            _LOGGER.warning("凭已保存凭据重新登录被拒绝: %s", err)
            return self.async_abort(reason="reauth_saved_invalid")
        except HiiggeError as err:
            _LOGGER.warning("凭已保存凭据重新登录异常: %s", err)
            return self.async_abort(reason="reauth_saved_unreachable")

        return await self._finish(
            api.session,
            self._entry_device(entry),
            base,
            account,
            pwd_hash=pwd_hash,
        )

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        entry = self._reauth_entry()
        if entry is None:
            return self.async_abort(reason="reauth_failed")
        self._hiigge_reauth_entry_id = entry.entry_id
        errors: dict[str, str] = {}
        if user_input is not None:
            base = entry.data.get(CONF_BASE_URL, BASE_CN)
            api = HiiggeApi(base)
            try:
                await api.login(user_input[CONF_ACCOUNT], user_input[CONF_PASSWORD])
            except HiiggeAuthError:
                errors["base"] = "invalid_auth"
            except HiiggeApiError as err:
                _LOGGER.warning("重新登录被服务端拒绝: %s", err)
                errors["base"] = "api_rejected"
            except HiiggeError:
                errors["base"] = "cannot_connect"
            else:
                device = self._entry_device(entry)
                return await self._finish(
                    api.session,
                    device,
                    base,
                    user_input[CONF_ACCOUNT],
                    # 顺手刷新保存的摘要，下次即可免密重登
                    pwd_hash=hash_password(user_input[CONF_PASSWORD]),
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_ACCOUNT, default=entry.data.get(CONF_ACCOUNT, "")
                    ): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_reauth_sms(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """重新认证时也能走验证码 —— 忘记密码的账号不必再抓包。"""
        errors: dict[str, str] = {}
        entry = self._reauth_entry()
        if entry is None:
            return self.async_abort(reason="reauth_failed")
        self._hiigge_reauth_entry_id = entry.entry_id
        base = entry.data.get(CONF_BASE_URL, BASE_CN)

        if user_input is not None:
            mobile = str(user_input[CONF_ACCOUNT]).strip()
            code = str(user_input.get(CONF_SMS_CODE, "")).strip()
            api = HiiggeApi(base)
            if code:
                try:
                    await api.login_sms(mobile, code)
                except HiiggeVerifyCodeError:
                    errors["base"] = "invalid_code"
                except HiiggeVerifyLockedError:
                    errors["base"] = "code_locked"
                except HiiggeRateLimitError:
                    errors["base"] = "code_rate_limited"
                except HiiggeError:
                    errors["base"] = "cannot_connect"
                else:
                    return await self._finish(
                        api.session,
                        self._entry_device(entry),
                        base,
                        mobile,
                    )
            else:
                try:
                    await api.send_verify_code(mobile)
                except HiiggeRateLimitError:
                    errors["base"] = "code_rate_limited"
                except HiiggeError:
                    errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="reauth_sms",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_ACCOUNT, default=entry.data.get(CONF_ACCOUNT, "")
                    ): str,
                    vol.Optional(CONF_SMS_CODE, default=""): str,
                }
            ),
            errors=errors,
            description_placeholders={
                "hint": "先留空验证码提交以获取短信，再填入 6 位验证码提交完成登录。"
            },
        )

    @staticmethod
    def _entry_device(entry) -> dict[str, Any]:
        """用已有条目里的信息重建设备字典，供 `_finish` 使用（reauth 路径）."""
        return {
            "deviceId": entry.data.get(CONF_DEVICE_ID),
            "deviceNickName": entry.title,
        }

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> OptionsFlow:
        return HiiggeOptionsFlow()


class HiiggeOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_SCAN_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                    ): vol.All(int, vol.Range(min=30, max=3600)),
                    # smart_type（品类）不在选项里暴露：它由设备型号决定，
                    # 见 catalog.py；用户在配置阶段也无需填写。
                    vol.Optional(
                        CONF_ENABLE_CONTROL,
                        default=self.config_entry.options.get(
                            CONF_ENABLE_CONTROL, DEFAULT_ENABLE_CONTROL
                        ),
                    ): bool,
                }
            ),
        )
