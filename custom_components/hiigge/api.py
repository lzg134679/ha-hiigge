"""Hiigge（70mai 智能宠物）云端 API 客户端.

全部端点、字段名、签名算法均为 2026-10-28 对 `api.70mai.com.cn` 的实测结果。

签名算法（依据客户端自身通信行为还原，集成可完全自主运行，不需要抓包/桥）
------------------------------------------------------
密钥从 App 进程内存的拼接串里取到，并用两个独立样本交叉验证：

    SECRET = "k98&^^^%d7s6NHF*^&)W(hsds12345"

验证码登录 `/accountApi/V2/userLogin` + 发码 `/accountApi/V3/sendUserVerifyCode`
（2026-10-29 纯协议探测确认，不需要抓包、不依赖手机）：

    sig  = md5(deviceType + "null" + mobile + ts + SECRET)
            ↑ 与密码登录同构，但 **pwdHash 那一段整个不存在**（不是空串、不是 null）
    发码体 = {mobile, deviceType, channel, uuid, ts, sig, type}
             type=2 登录 / type=1 注册（注册会报 "mobile user alreay exist"）
    登录取值字段 = **mobileVerifyCode**（不是 verifyCode / code / smsCode 之类）
    登录体 = {mobile, mobileVerifyCode, deviceType, channel, uuid, ts, sig}

判定手段（本项目通用技巧 —— 服务端 Jackson 为严格模式，可直接当 oracle 用）：
* 字段名不存在 → `UnrecognizedPropertyException: Unrecognized field "xxx" (Class ...UserLoginDTO)`
* 字段名存在但值不对 → 业务错误（"验证码无效" 5002006 / "校验验证码过于频繁" 5002002）
* 签名不对 → `sig not passed` / `签名校验不通过！`
逐个提交候选字段名，看错误是否从 Unrecognized 变成业务错误，即可枚举出整个 DTO。
`sendUserVerifyCode` 对必填字段另有 `[PARAMETER][xxx__SignCheck.arg0.字段][may not be null]` 提示。
（验证码登录页在 Charles 里抓不到是正常现象：App 的 Dart HttpClient 不走系统代理，
只有设备详情页的部分请求经过原生网络栈，所以只能从协议侧还原。）

通用接口（设备信息、状态、控制等）：

    sig = md5(token + uuid + channel + ts + SECRET)

密码登录 `/accountApi/V3/userLoginPwd`（2026-10-28 frida 抓包修正）：

    pwdHash = md5(明文密码 + SECRET)        ← 无 "dashcam" 前缀
    sig     = md5(deviceType + "null" + mobile + pwdHash + ts + SECRET)
               ↑ "null" 在 mobile 之前（token 占位）
    账号字段是 mobile（手机号），deviceType = 74

实测结论：
* 设备接口只校验 `sig` 的覆盖面，`deviceId` 等业务字段不参与；
* `ts` 是毫秒时间戳，服务端接受约 5 分钟窗口，所以每次请求现算即可；
* 拿到 token 后可长期使用，无需反复登录；
* 密码登录用 frida hook 抓真实请求验证通过（两账号均可登录）。

验证记录（2026-10-28）：
* 自主签名调 `getDeviceInfo` / `getHiiggeDeviceStatus` 均返回 200；
* 登录接口用假账号测试，错误从 `sig not passed` 变为 `can Not find accountUser`，
  说明签名已被服务端接受。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import ssl
import time
import uuid as uuid_lib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .catalog import DEFAULT_SMART_TYPE, decode_status_for

_LOGGER = logging.getLogger(__name__)

# App 私有签名密钥（从运行内存的签名输入串中取得，已交叉验证）
SECRET = "k98&^^^%d7s6NHF*^&)W(hsds12345"
# 密码摘要：直接 md5(明文 + SECRET)，无前缀（2026-10-28 抓包修正）

BASE_CN = "https://api.70mai.com.cn"
BASE_INTL = "https://int-api.70mai.com"
BASE_EU = "https://eu-api.70mai.com"
BASE_NA = "https://us-api.70mai.com"
DEFAULT_BASE_URL = BASE_CN

# Hiigge 国服 App 的渠道号（实测；不是 70mai 车机的 3001013）
DEFAULT_CHANNEL = 74002001
# 设备品类（smartType）与硬件型号的对应关系集中在 `catalog.py`；
# 饮水机 PI3501 的 smartType = 49。此处通过 import 再导出，
# 让既有的 `from .api import DEFAULT_SMART_TYPE` 调用方无需改动。


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def hash_password(plain: str) -> str:
    """密码摘要：md5(明文 + SECRET).

    2026-10-28 frida hook 抓包修正：**没有** "dashcam" 前缀，
    就是 md5(plainPassword + SECRET)。
    """
    return md5_hex(f"{plain}{SECRET}")


def sign_general(token: str, uid: str, channel: int, ts: int) -> str:
    """通用接口签名：md5(token + uuid + channel + ts + SECRET)."""
    return md5_hex(f"{token}{uid}{channel}{ts}{SECRET}")


def sign_login(device_type: int, mobile: str, pwd_hash: str, ts: int) -> str:
    """登录签名：md5(deviceType + "null" + mobile + pwdHash + ts + SECRET).

    2026-10-28 frida hook 抓包修正：
    * "null" 在 mobile **之前**（token 占位），不是之后；
    * 账号字段是 mobile（手机号），不是 email；
    * deviceType 用 74。
    """
    return md5_hex(f"{device_type}null{mobile}{pwd_hash}{ts}{SECRET}")


def sign_phone(device_type: int, mobile: str, ts: int) -> str:
    """无密码场景签名（发验证码 / 验证码登录）：md5(deviceType + "null" + mobile + ts + SECRET).

    与 `sign_login` 同构，区别仅在于 **pwdHash 整段不存在**。
    这一点容易写错：补成空串或 "null" 都会得到 `签名校验不通过！`。
    """
    return md5_hex(f"{device_type}null{mobile}{ts}{SECRET}")

EP_DEVICES = "/HiiggeHomeDeviceApi/userDevices"
EP_HOME_LIST = "/hiiggeHomeApi/homeList"
EP_HOME_DETAIL = "/hiiggeHomeApi/homeDetail"
EP_DEVICE_INFO = "/hiigge/device/api/getDeviceInfo"
EP_DEVICE_STATUS = "/hiigge/device/api/getHiiggeDeviceStatus"
EP_SET_CONFIG = "/hiigge/device/api/setUserDeviceConfig"
EP_CLEAR_WATER_LOW = "/hiigge/device/api/clearWaterVolumeLowStatus"
# 喝水统计（2026-10-29 实测）：家庭维度接口，参数是 homeId 而不是 deviceId
EP_DRINK_TODAY = "/HiiggeHomeDataSummaryApi/getHomeTodayDrinkData"
EP_DRINK_WEEK = "/HiiggeHomeDataSummaryApi/getHomeWeekDrinkData"
EP_DRINK_MONTH = "/HiiggeHomeDataSummaryApi/getHomeMonthDrinkData"
EP_DRINK_MARK = "/HiiggeHomeDataSummaryApi/getHomeDrinkValidMark"
EP_LOGIN_SMS = "/accountApi/V2/userLogin"
EP_LOGOUT = "/accountApi/V3/userLogOut"
EP_SEND_CODE_V2 = "/accountApi/V2/userGetVerifyCodeWithDeviceType"
EP_SEND_CODE = "/accountApi/V3/sendUserVerifyCode"
EP_LOGIN_PWD = "/accountApi/V3/userLoginPwd"
EP_TS = "/baseServiceApi/V2/getTs"

# 验证码登录相关（2026-10-29 协议探测确认）
# 登录取值字段名就叫 mobileVerifyCode —— DTO 见
# com.banya.carMirror.openapi.v2.dto.V2.AccountApiV2UserLoginDTO
SMS_CODE_FIELD = "mobileVerifyCode"
# 发码 type：1=注册（已注册会报 mobile user alreay exist），2=登录
VERIFY_CODE_TYPE_LOGIN = 2
VERIFY_CODE_TYPE_REGISTER = 1

# 服务端业务错误码
ERR_CODE_PASSWORD_INCORRECT = 5002011  # 密码不正确（password not correct）
ERR_CODE_VERIFY_INVALID = 5002006  # 验证码无效
ERR_CODE_VERIFY_TOO_FREQUENT = 5002002  # 发送/校验验证码过于频繁
ERR_CODE_VERIFY_LOCKED = 5002003  # 连续 5 次校验失败，需重新发送验证码
ERR_CODE_MOBILE_EXISTS = 5002008  # 手机号已注册（type=1 时出现）


class HiiggeError(Exception):
    """通用错误."""


class HiiggeApiError(HiiggeError):
    """服务端明确返回了业务错误（不是网络问题）.

    用于把"账号/参数被服务端拒绝"与"连不上服务器"区分开——
    前者不该提示成"网络异常"。
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class HiiggeAuthError(HiiggeError):
    """token 失效，或账号/密码不正确."""


class HiiggeSignatureError(HiiggeError):
    """签名校验不通过——需要重新抓包换一个新的会话四元组."""


class HiiggeConnectionError(HiiggeError):
    """传输层失败."""


class HiiggeVerifyCodeError(HiiggeError):
    """验证码无效或已过期（服务端 5002006）."""


class HiiggeRateLimitError(HiiggeError):
    """验证码发送或校验过于频繁（服务端 5002002），需等待一段时间."""


class HiiggeVerifyLockedError(HiiggeError):
    """同一验证码连续校验失败达 5 次（服务端 5002003），必须重新下发验证码."""


@dataclass
class Session:
    """登录后长期使用的会话：token + 客户端 uuid + channel.

    签名不再需要缓存——每个请求都按当前时间现算（见 `sign_general`）。
    `sig` / `ts` 字段仅为兼容旧抓包数据保留，实际请求不使用。
    """

    token: str
    uuid: str = field(default_factory=lambda: str(uuid_lib.uuid4()).upper())
    sig: str = ""
    ts: int = 0
    channel: int = DEFAULT_CHANNEL

    @classmethod
    def from_capture(cls, data: dict[str, Any]) -> "Session":
        """从 Charles 里复制的请求体（dict）构造（仅用于兼容历史配置）.

        兼容字段被写成 78.0 / 7.8001001E7 这种浮点形态。
        """
        def _int(value: Any, default: int = 0) -> int:
            try:
                return int(float(value))
            except (TypeError, ValueError):
                return default

        token = str(data.get("token") or "").strip()
        uid = str(data.get("uuid") or "").strip()
        if not (token and uid):
            raise ValueError("请求体里缺少 token / uuid")
        return cls(
            token=token,
            uuid=uid,
            sig=str(data.get("sig") or ""),
            ts=_int(data.get("ts")),
            channel=_int(data.get("channel"), DEFAULT_CHANNEL),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "uuid": self.uuid,
            "sig": self.sig,
            "ts": self.ts,
            "channel": self.channel,
        }


@dataclass
class HiiggeDevice:
    raw: dict[str, Any] = field(default_factory=dict)
    status: dict[str, Any] = field(default_factory=dict)

    @property
    def device_id(self) -> str:
        return str(self.raw.get("deviceId") or "")

    @property
    def name(self) -> str:
        return str(self.raw.get("deviceNickName") or self.device_id)

    @property
    def device_type(self) -> int:
        return int(self.raw.get("type") or self.raw.get("deviceType") or 0)

    @property
    def device_module(self) -> int:
        return int(self.raw.get("module") or self.raw.get("deviceModule") or 0)

    @property
    def device_channel(self) -> int:
        return int(self.raw.get("channel") or self.raw.get("deviceChannel") or 0)

    @property
    def model(self) -> str:
        proto = self.raw.get("model") or self.raw.get("deviceProto") or self.raw.get("module")
        return f"PI{proto}" if proto else "Hiigge"

    @property
    def online(self) -> bool | None:
        value = self.status.get("online")
        if value is None:
            value = self.raw.get("isOnline")
        return None if value is None else bool(value)


class HiiggeApi:
    """POST-only JSON 客户端（标准库实现）."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        session: Session | None = None,
        verify_ssl: bool = True,
        timeout: float = 20.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.cert_warning = False
        self.last_error: str | None = None
        # 未登录阶段（发码 → 输码登录）共用同一个客户端 uuid
        self._client_uuid: str = ""

    # -- transport ---------------------------------------------------------
    def _call(self, path: str, body: dict[str, Any]) -> Any:
        import urllib.error
        import urllib.request

        def _do(verify: bool) -> tuple[int, bytes]:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{self.base_url}{path}",
                data=json.dumps(body).encode(),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Charset": "UTF-8",
                    # 伪装成 App 的 Dart HttpClient（实测服务端不校验 UA，
                    # 但混入正常流量可降低被指纹识别的概率）
                    "User-Agent": "Dart/3.11 (dart:io)",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return resp.status, resp.read()

        try:
            status, raw = _do(self.verify_ssl)
        except urllib.error.HTTPError as err:
            status, raw = err.code, err.read()
        except Exception as err:  # noqa: BLE001
            reason = getattr(err, "reason", err)
            is_cert = isinstance(reason, ssl.SSLError) or "CERTIFICATE_VERIFY" in str(err)
            if not is_cert or not self.verify_ssl:
                raise HiiggeConnectionError(f"{path}: {reason}") from err
            # 服务端证书链中间证书已过期（叶证书仍有效），降级一次
            _LOGGER.warning("证书链校验失败（%s），本次改用不校验继续", reason)
            self.cert_warning = True
            try:
                status, raw = _do(False)
            except urllib.error.HTTPError as err2:
                status, raw = err2.code, err2.read()
            except Exception as err2:  # noqa: BLE001
                raise HiiggeConnectionError(f"{path}: {err2}") from err2

        text = raw.decode("utf-8", "replace")
        if status == 404:
            raise HiiggeError(f"{path}: 接口不存在(404)")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            raise HiiggeError(f"{path}: HTTP {status} {text[:300]}") from None

        if isinstance(payload, dict) and payload.get("error"):
            msg = str(payload.get("errorMessage") or "")
            code = payload.get("errorCode")
            self.last_error = msg
            # 错误码优先判定：文案里的“过期”既可能是 token 也可能是验证码
            if code == ERR_CODE_VERIFY_INVALID:
                raise HiiggeVerifyCodeError(msg)
            if code == ERR_CODE_VERIFY_TOO_FREQUENT:
                raise HiiggeRateLimitError(msg)
            if code == ERR_CODE_VERIFY_LOCKED:
                raise HiiggeVerifyLockedError(msg)
            if code == ERR_CODE_PASSWORD_INCORRECT:
                # 密码错是账号问题，必须走 AuthError，
                # 否则会被上层笼统地显示成"网络异常"
                raise HiiggeAuthError(f"{path}: {msg}")
            low = msg.lower()
            if "签名" in msg or "sig" in low or "过期" in msg:
                raise HiiggeSignatureError(f"{path}: {msg}")
            if "token" in low:
                raise HiiggeAuthError(f"{path}: {msg}")
            if "password" in low or "密码" in msg:
                raise HiiggeAuthError(f"{path}: {msg}")
            # 其余是服务端明确的业务拒绝（参数/权限等），与网络无关
            raise HiiggeApiError(f"{path}: {msg}", code=code)
        return payload.get("resultBodyObject") if isinstance(payload, dict) else payload

    async def _post(self, path: str, body: dict[str, Any]) -> Any:
        return await asyncio.get_running_loop().run_in_executor(None, self._call, path, body)

    def _body(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """构造请求体：ts 与 sig 每次都按当前时间现算."""
        if not self.session:
            raise HiiggeAuthError("缺少会话（需要先登录拿到 token）")
        ts = int(time.time() * 1000)
        body: dict[str, Any] = {
            "uuid": self.session.uuid,
            "channel": self.session.channel,
            "ts": ts,
            "token": self.session.token,
            "sig": sign_general(self.session.token, self.session.uuid, self.session.channel, ts),
        }
        if extra:
            body.update(extra)
        return body

    # -- 设备 --------------------------------------------------------------
    async def devices(self) -> list[dict[str, Any]]:
        """个人设备（不含挂在家庭下的，通常为空，仅供排查）."""
        data = await self._post(EP_DEVICES, self._body())
        return _device_list(data)

    async def homes(self) -> list[dict[str, Any]]:
        """账号下的所有家庭（含共享家庭）."""
        data = await self._post(EP_HOME_LIST, self._body())
        return data if isinstance(data, list) else []

    async def all_devices(self) -> list[dict[str, Any]]:
        """遍历所有家庭收集设备。

        实测：设备不在 `userDevices` 里，而是挂在某个家庭下
        （本项目这台饮水机就在「共享家庭」里），所以要逐家庭查 homeDetail。
        """
        result: list[dict[str, Any]] = []
        for home in await self.homes():
            home_id = home.get("homeId")
            if not home_id:
                continue
            try:
                detail = await self._post(EP_HOME_DETAIL, self._body({"homeId": home_id}))
            except HiiggeError as err:
                _LOGGER.debug("家庭 %s 查询失败: %s", home_id, err)
                continue
            if isinstance(detail, dict):
                for dev in detail.get("devices") or []:
                    if isinstance(dev, dict) and dev.get("deviceId"):
                        # 带上所属家庭：喝水统计等接口需要 homeId，配置阶段顺手存下来
                        result.append({**dev, "_homeId": str(home_id)})
        return result

    async def find_home_id(self, device_id: str) -> str | None:
        """反查设备所属的家庭 ID.

        喝水统计接口是**家庭维度**（要 `homeId`，传 `deviceId` 会被 Jackson 拒绝），
        而配置条目里只存了 `deviceId`。老条目没有 `homeId` 时用这个方法补一次。
        """
        for home in await self.homes():
            home_id = home.get("homeId")
            if not home_id:
                continue
            try:
                detail = await self._post(EP_HOME_DETAIL, self._body({"homeId": home_id}))
            except HiiggeError as err:
                _LOGGER.debug("家庭 %s 查询失败: %s", home_id, err)
                continue
            for dev in (detail or {}).get("devices") or []:
                if str(dev.get("deviceId")) == str(device_id):
                    return str(home_id)
        return None

    async def device_info(self, device_id: str) -> dict[str, Any]:
        data = await self._post(EP_DEVICE_INFO, self._body({"deviceId": device_id}))
        return data if isinstance(data, dict) else {}

    async def device_status(self, dev: dict[str, Any], smart_type: int = DEFAULT_SMART_TYPE) -> dict[str, Any]:
        """返回解码后的状态字典."""
        body = self._body(
            {
                "deviceId": dev.get("deviceId"),
                "deviceType": dev.get("type"),
                "deviceModule": dev.get("module"),
                "deviceChannel": dev.get("channel"),
                "smartType": smart_type,
            }
        )
        data = await self._post(EP_DEVICE_STATUS, body)
        if not isinstance(data, dict):
            return {}
        hex_str = data.get("dataHexStr")
        if not hex_str:
            return {}
        decoded = decode_status_for(smart_type, hex_str)
        decoded["refresh_ts"] = data.get("refreshTs")
        return decoded

    # -- 喝水统计（家庭维度） ----------------------------------------------
    async def today_drink(
        self, home_id: str, when: datetime | None = None
    ) -> dict[str, Any]:
        """今日喝水统计 —— 对应 App 首页的「N 次」与详情页的分时折线.

        2026-10-29 实测返回：

            {"allDrinkFrequency": 20,                     # 今日总次数（首页那个数字）
             "averageDrinkDuration": 21,                  # 平均每次时长（秒）
             "drinkFrequencyCompareWithAverageLast": -20, # 较日均值的差（截图“少了20次”）
             "oneHourDataList": [{"year":2026,"month":10,"day":29,
                                  "hour":13,"thisHourDrinkDuration":4}]}

        注意 `hour` / `minute` 是**必填**：服务端按「截止到该时刻」统计
        （App 文案就是“截止 14:00”），不是按整天算。
        """
        now = when or datetime.now()
        body = {
            "homeId": home_id,
            "year": now.year,
            "month": now.month,
            "day": now.day,
            "hour": now.hour,
            "minute": now.minute,
        }
        data = await self._post(EP_DRINK_TODAY, self._body(body))
        return data if isinstance(data, dict) else {}

    async def week_drink(
        self, home_id: str, when: datetime | None = None
    ) -> dict[str, Any]:
        """周统计（7 天，按 thisDayDrinkDuration 给出每天时长）."""
        now = when or datetime.now()
        body = {
            "homeId": home_id,
            "year": now.year,
            "month": now.month,
            "day": now.day,
        }
        data = await self._post(EP_DRINK_WEEK, self._body(body))
        return data if isinstance(data, dict) else {}

    async def month_drink(
        self, home_id: str, when: datetime | None = None
    ) -> dict[str, Any]:
        """月统计（当月每天时长）."""
        now = when or datetime.now()
        body = {
            "homeId": home_id,
            "year": now.year,
            "month": now.month,
            "day": now.day,
        }
        data = await self._post(EP_DRINK_MONTH, self._body(body))
        return data if isinstance(data, dict) else {}

    async def drink_valid_marks(
        self, home_id: str, start: datetime, end: datetime
    ) -> dict[str, Any]:
        """有数据的日子（月历上打点用）."""
        body = {
            "homeId": home_id,
            "startYear": start.year,
            "startMonth": start.month,
            "endYear": end.year,
            "endMonth": end.month,
        }
        data = await self._post(EP_DRINK_MARK, self._body(body))
        return data if isinstance(data, dict) else {}

    # -- 控制（写操作，需 enable_control） ---------------------------------
    async def set_device_config(self, device_id: str, configs: dict[str, Any]) -> Any:
        return await self._post(
            EP_SET_CONFIG, self._body({"deviceId": device_id, "deviceConfigs": configs})
        )

    async def clear_water_low(self, device_id: str) -> Any:
        return await self._post(EP_CLEAR_WATER_LOW, self._body({"deviceId": device_id}))

    async def clear_water_low_smart(self, dev: dict[str, Any], smart_type: int = DEFAULT_SMART_TYPE) -> Any:
        return await self._post(
            EP_CLEAR_WATER_LOW,
            self._body(
                {
                    "deviceId": dev.get("deviceId"),
                    "deviceType": dev.get("type"),
                    "deviceModule": dev.get("module"),
                    "deviceChannel": dev.get("channel"),
                    "smartType": smart_type,
                }
            ),
        )

    # -- 登录 --------------------------------------------------------------
    async def login(
        self, mobile: str, password: str, device_type: int = 74
    ) -> dict[str, Any]:
        """手机号密码登录，成功后把 token 写进 self.session.

        2026-10-28 frida hook 抓包验证的真实请求格式:
        * 账号字段是 **mobile**（不是 email）
        * **deviceType = 74**
        * 密码哈希：md5(明文 + SECRET)（无 "dashcam" 前缀）
        * 签名：md5(deviceType + "null" + mobile + pwdHash + ts + SECRET)

        * **不传 deviceToken**——服务端不校验，传了也没用；
          App 传的是推送 token（小米推送/FCM），与登录鉴权无关
        * **uuid 随机生成**——每个集成实例独立，服务端不校验格式/来源
        * **UA 伪装 Dart HttpClient**——服务端不校验，但混入正常流量
        * **token 长期复用**——配置流保存 token，不频繁重新登录
        * 服务端对登录请求体字段严格校验（多余字段直接 400），
          不要随意添加额外字段
        * 实测 10 次/3秒快速登录不限频、5 次错误密码不锁号
        """
        return await self.login_with_hash(
            mobile, hash_password(password), device_type
        )

    async def login_with_hash(
        self, mobile: str, pwd_hash: str, device_type: int = 74
    ) -> dict[str, Any]:
        """用已保存的密码摘要登录（免明文密码）.

        登录请求只使用 `md5(明文 + SECRET)` 这一个字段，签名也基于它，
        因此把该摘要存下来就能重复换 token，无需保留明文密码。
        摘要不可逆推明文，但仍等同登录凭据，属于敏感数据。
        """
        if not pwd_hash:
            raise HiiggeAuthError("缺少已保存的密码凭据，请改用密码或验证码登录")
        uid = self.session.uuid if self.session else str(uuid_lib.uuid4()).upper()
        ts = int(time.time() * 1000)
        body = {
            "channel": DEFAULT_CHANNEL,
            "deviceType": device_type,
            "uuid": uid,
            "passWord": pwd_hash,
            "sig": sign_login(device_type, mobile, pwd_hash, ts),
            "ts": ts,
            "mobile": mobile,
        }
        data = await self._post(EP_LOGIN_PWD, body)
        token = None
        if isinstance(data, dict):
            token = data.get("token") or data.get("userToken")
        if not token:
            raise HiiggeAuthError(f"登录未返回 token: {str(data)[:200]}")
        self.session = Session(token=str(token), uuid=uid, channel=DEFAULT_CHANNEL)
        return data if isinstance(data, dict) else {"token": token}

    async def logout(self) -> Any:
        return await self._post(EP_LOGOUT, self._body())

    # -- 验证码登录 --------------------------------------------------------
    @property
    def client_uuid(self) -> str:
        """客户端 uuid —— 同一实例内保持不变.

        发码与随后的登录必须携带同一个 uuid，否则服务端无法把验证码与会话对上；
        会话已建立时直接复用会话里的 uuid。
        """
        if self.session:
            return self.session.uuid
        if not getattr(self, "_client_uuid", ""):
            self._client_uuid = str(uuid_lib.uuid4()).upper()
        return self._client_uuid

    async def send_verify_code(
        self, mobile: str, device_type: int = 74, code_type: int = VERIFY_CODE_TYPE_LOGIN
    ) -> Any:
        """发送短信验证码（不需要 token，签名用 `sign_phone`）.

        `type` 是验证码用途：2=登录（默认），1=注册。实测 type=2 返回
        `{"resultBodyObject": true, ...}` 即已下发；同一手机号再次发送会命中
        频控（5002002「校验验证码过于频繁」），属于服务端策略，非接口问题。
        """
        ts = int(time.time() * 1000)
        body = {
            "mobile": mobile,
            "deviceType": device_type,
            "type": code_type,
            "channel": DEFAULT_CHANNEL,
            "uuid": self.client_uuid,
            "ts": ts,
            "sig": sign_phone(device_type, mobile, ts),
        }
        return await self._post(EP_SEND_CODE, body)

    async def login_sms(self, mobile: str, code: str, device_type: int = 74) -> str:
        """手机号 + 短信验证码登录，成功后把 token 写进 self.session.

        2026-10-29 实测通过的请求体：

            {"mobile": ..., "mobileVerifyCode": "558428", "deviceType": 74,
             "channel": 74002001, "uuid": ..., "ts": ..., "sig": ...}

        sig = md5(deviceType + "null" + mobile + ts + SECRET)，注意**没有**密码段。
        返回 structure 与服务端一致：token / userID / userName / newUser 等。
        """
        ts = int(time.time() * 1000)
        uid = self.client_uuid
        body = {
            "mobile": mobile,
            SMS_CODE_FIELD: code,
            "deviceType": device_type,
            "channel": DEFAULT_CHANNEL,
            "uuid": uid,
            "ts": ts,
            "sig": sign_phone(device_type, mobile, ts),
        }
        data = await self._post(EP_LOGIN_SMS, body)
        token = None
        if isinstance(data, dict):
            token = data.get("token") or data.get("userToken")
        if not token:
            raise HiiggeAuthError(f"验证码登录未返回 token: {str(data)[:200]}")
        self.session = Session(
            token=str(token), uuid=uid, channel=DEFAULT_CHANNEL
        )
        return str(token)

    async def server_time(self) -> Any:
        return await self._post(EP_TS, {})


def _as_int(value: Any, default: int | None = None) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def summarize_today_drink(data: dict[str, Any], day: datetime) -> dict[str, Any]:
    """把 `today_drink` 的原始返回压平，供实体直接消费.

    `hourly` 里只保留服务端真正给回来的小时（没喝水的小时不会出现），
    所以最后一项就是「最近一次喝水所在的时段」。
    """
    hourly: list[dict[str, int]] = []
    for item in data.get("oneHourDataList") or []:
        if not isinstance(item, dict):
            continue
        hour = _as_int(item.get("hour"))
        if hour is None:
            continue
        hourly.append(
            {"hour": hour, "duration": _as_int(item.get("thisHourDrinkDuration"), 0) or 0}
        )
    hourly.sort(key=lambda x: x["hour"])

    last = hourly[-1] if hourly else None
    last_ts: datetime | None = None
    if last is not None:
        try:
            last_ts = day.replace(hour=last["hour"], minute=0, second=0, microsecond=0)
        except ValueError:
            last_ts = None

    return {
        "count": _as_int(data.get("allDrinkFrequency")),
        "duration_sec": sum(item["duration"] for item in hourly),
        "avg_duration_sec": _as_int(data.get("averageDrinkDuration")),
        "compare_avg": _as_int(data.get("drinkFrequencyCompareWithAverageLast")),
        "hourly": hourly,
        "last_hour": last["hour"] if last else None,
        "last_ts": last_ts,
        "active_hours": len(hourly),
    }


def _device_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("devices", "deviceList", "list", "records", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return [d for d in value if isinstance(d, dict)]
        if data.get("deviceId"):
            return [data]
    return []
