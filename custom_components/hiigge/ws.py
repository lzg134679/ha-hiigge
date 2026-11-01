"""Hiigge WebSocket 控制通道（协议依据客户端自身通信行为还原，2026-10-28 实测）.

链路：
    POST /hiiggeWebsocketApi/getWebsocketAddress
      → {websocketAddress, websocketToken, websocketAesKey}
    WebSocket 连接 websocketAddress
    → 发送鉴权文本帧 {"operateId":10000000,"handshakeToken":"<token>","ts":<ms>}
    ← {"ackCode":200,"isAck":true,...}
    → 发送加密文本帧（hex 字符串）：
        明文 = {"content":"<SmartPacket的hex>","deviceId":"...","deviceType":74,
                "operateId":"<uuid>","target":2,"ts":<ms>}
        密文 = AES/CBC/PKCS5Padding(key=websocketAesKey,
                                    iv=000102030405060708090a0b0c0d0e0f)
        帧   = 密文的十六进制字符串（文本帧）

SmartPacket 结构（protobuf）：
    field 1  type = 49（PET_DRINKING_FOUNTAIN 设备类型）
    field 2  id   = 任意递增整数
    field 51 petDrinkingFountain:
        field 4  drainageMode {1:drainage_on, 2:mode, 3:intermittent_wait_min}
        field 7  filterElement（清零滤芯）
        field 10 drainageGear {1:level}
        field 11 petColorConfig {1:color}   ← 感应灵敏度

枚举：
    DrainageMode.Mode: 1=间歇出水  2=感应出水  3=持续出水
    DrainageGear.Level: 1=低  2=中  3=高
    PetColorConfig: 1=浅色宠物(标准)  2=深色宠物(增强)

实现要点（HA 环境）
--------------------
整个 WebSocket 会话是**阻塞式**的（取地址用标准库 + 同步 WS 客户端），
因此统一放进 executor 执行，避免卡住 HA 的事件循环。
`send_command()` 对外仍是 async 接口，实体层直接 await 即可。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any

_LOGGER = logging.getLogger(__name__)

# 固定 IV（从 Cipher.init hook 实测取得，每次会话均相同）
FIXED_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

# WS 协议里的设备类型编号（注意：不是 REST 的 78）
WS_DEVICE_TYPE = 74

# 等待设备 ack 的最长时间（秒）
DEFAULT_TIMEOUT = 12.0


# ---------------------------------------------------------------- protobuf 编码
def _varint(value: int) -> bytes:
    out = b""
    while value > 0x7F:
        out += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    return out + bytes([value])


def _field_varint(num: int, value: int) -> bytes:
    return _varint((num << 3) | 0) + _varint(value)


def _field_bytes(num: int, data: bytes) -> bytes:
    return _varint((num << 3) | 2) + _varint(len(data)) + data


_cmd_counter = 16  # 从 17 开始递增（id=1 会被设备拒绝 NOT_SUPPORT）


def _next_id() -> int:
    global _cmd_counter
    _cmd_counter += 1
    return _cmd_counter


def _packet(inner: bytes, cmd_id: int | None = None) -> bytes:
    """SmartPacket{type=49, id=?, petDrinkingFountain=inner}.

    cmd_id 不传时自增（从 17 开始）。注意：模式命令用 id=5，
    滤芯重置用 id=11，滤芯查询用 id=12，是 App 实测的固定值。
    """
    if cmd_id is None:
        cmd_id = _next_id()
    return _field_varint(1, 49) + _field_varint(2, cmd_id) + _field_bytes(51, inner)


def cmd_drainage_mode(mode: int, wait_min: int = 45, on: int = 1) -> bytes:
    """出水方式：1=间歇 2=感应 3=持续；wait_min = 间歇间隔（分钟）；on=0 关闭出水.

    App 实测：id 固定为 5，wait_min 默认 45（当前配置值）。
    """
    inner = _field_varint(1, on) + _field_varint(2, mode) + _field_varint(3, wait_min)
    return _packet(_field_bytes(4, inner), cmd_id=5)


def cmd_drainage_gear(level: int) -> bytes:
    """出水档位：1=低 2=中 3=高. App 实测 id=17."""
    return _packet(_field_bytes(10, _field_varint(1, level)), cmd_id=17)


def cmd_pet_color(color: int) -> bytes:
    """感应灵敏度：1=浅色宠物 2=深色宠物. App 实测 id=19."""
    return _packet(_field_bytes(11, _field_varint(1, color)), cmd_id=19)


# OptionalSwitcher 枚举（CommonProtos$OptionalSwitcher）：0=NO_FEATURE 1=ON 2=OFF
SWITCHER_ON = 1
SWITCHER_OFF = 2


def cmd_child_lock(turn_on: bool) -> bytes:
    """童锁：SmartPacket{1:49, 2:9, 51:{6: 1|2}}.

    id=9 来自 PetDrinkingFountainID.SET_CHILD_LOCK_MODE，
    字段 6 是该 message 的 oneof case（child_lock_mode）。
    2026-10-30 实测：下发后 1.5s 内状态翻转。
    """
    return _packet(
        _field_varint(6, SWITCHER_ON if turn_on else SWITCHER_OFF), cmd_id=9
    )


def cmd_scour_mode(turn_on: bool) -> bytes:
    """强力冲刷：SmartPacket{1:49, 2:7, 51:{5: 1|2}}.

    id=7 = PetDrinkingFountainID.SET_SCOUR_MODE，字段 5 = oneof case(scour_mode)。
    2026-10-30 实测通过。
    """
    return _packet(
        _field_varint(5, SWITCHER_ON if turn_on else SWITCHER_OFF), cmd_id=7
    )


def cmd_filter_reset() -> bytes:
    """滤芯重置——裸 SmartPacket{type=49, id=11}，**不带** petDrinkingFountain payload.

    这是 App 实际发送的格式（frida hook 抓取确认）：
    ``0831100b`` = field1(49) + field2(11)，无其他字段。
    """
    return _field_varint(1, 49) + _field_varint(2, 11)


def cmd_filter_query() -> bytes:
    """滤芯查询——裸 SmartPacket{type=49, id=12}，触发 App 刷新滤芯状态."""
    return _field_varint(1, 49) + _field_varint(2, 12)


# ---------------------------------------------------------------- AES 封装
def _pkcs7_pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def encrypt_frame(key_hex: str, plaintext: str) -> str:
    """把 JSON 明文加密成 WS 文本帧（hex 字符串）。

    帧格式：AES-CBC 密文 + CRC32(密文) 小端 4 字节，整体 hex 编码。
    """
    import struct
    import zlib

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes.fromhex(key_hex)
    data = _pkcs7_pad(plaintext.encode("utf-8"))
    enc = Cipher(algorithms.AES(key), modes.CBC(FIXED_IV)).encryptor()
    ct = enc.update(data) + enc.finalize()
    crc = struct.pack("<I", zlib.crc32(ct) & 0xFFFFFFFF)
    return (ct + crc).hex()


def decrypt_frame(key_hex: str, frame_hex: str) -> str:
    """把收到的 hex 帧解密成 JSON 明文（去掉末尾 4 字节 CRC32）."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes.fromhex(key_hex)
    raw = bytes.fromhex(frame_hex)
    # CRC32 在尾部：去掉最后 4 字节得到 AES 密文
    ct = raw[:-4] if len(raw) % 16 == 4 else raw
    if len(ct) % 16:
        return ""
    dec = Cipher(algorithms.AES(key), modes.CBC(FIXED_IV)).decryptor()
    out = dec.update(ct) + dec.finalize()
    pad = out[-1]
    if 1 <= pad <= 16:
        out = out[:-pad]
    return out.decode("utf-8", "replace")


# ---------------------------------------------------------------- 阻塞式会话
def _ws_address(api: Any) -> dict[str, Any]:
    """取 WS 地址/鉴权 token/AES key（同步，标准库实现，需在 executor 内调用）."""
    import ssl
    import urllib.request

    from .api import sign_general

    ts0 = int(time.time() * 1000)
    body = {
        "uuid": api.session.uuid,
        "channel": api.session.channel,
        "ts": ts0,
        "token": api.session.token,
        "sig": sign_general(api.session.token, api.session.uuid, api.session.channel, ts0),
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        f"{api.base_url}/hiiggeWebsocketApi/getWebsocketAddress",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            payload = json.loads(resp.read().decode())
    except Exception as err:  # noqa: BLE001
        raise RuntimeError(f"获取 WS 地址失败: {err}") from err

    info = payload.get("resultBodyObject") if isinstance(payload, dict) else None
    if not isinstance(info, dict) or not info.get("websocketAddress"):
        raise RuntimeError(f"获取 WS 地址失败: {str(payload)[:300]}")
    return info


def _connect(address: str):
    """建立 WS 连接（wss 时跳过证书校验——服务端证书链在部分设备上不完整）."""
    import ssl

    from websockets.sync.client import connect

    if address.startswith("wss://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return connect(address, open_timeout=10, close_timeout=3, ssl=ctx)
    return connect(address, open_timeout=10, close_timeout=3)


def _ssl_context(address: str):
    import ssl

    if not address.startswith("wss://"):
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _session_async(
    address: str,
    ws_token: str,
    aes_key: str,
    frame: str,
    timeout: float,
) -> dict[str, Any]:
    """异步实现——仅在环境缺少 websockets.sync（<12.0）时作为回退使用."""
    import websockets

    async with websockets.connect(
        address, open_timeout=10, close_timeout=3, ssl=_ssl_context(address)
    ) as ws:
        auth = {
            "operateId": 10000000,
            "handshakeToken": ws_token,
            "ts": int(time.time() * 1000),
        }
        await ws.send(json.dumps(auth))
        try:
            await asyncio.wait_for(ws.recv(), timeout=6)
        except asyncio.TimeoutError:
            _LOGGER.warning("WS 鉴权无响应，继续尝试发送")

        await ws.send(frame)
        for _ in range(3):
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
            except asyncio.TimeoutError:
                break
            parsed = _parse_message(aes_key, msg)
            if parsed is not None:
                return parsed
    return {"ok": True, "note": "命令已发送，无显式 ack"}


def _parse_message(aes_key: str, msg: Any) -> dict[str, Any] | None:
    """解析一帧下行消息：hex 密文或明文 JSON，无法识别时返回 None."""
    if not isinstance(msg, str) or not msg:
        return None
    if msg.startswith("{"):
        try:
            return json.loads(msg)
        except json.JSONDecodeError:
            return {"raw": msg}
    if all(c in "0123456789abcdefABCDEF" for c in msg):
        try:
            plain = decrypt_frame(aes_key, msg)
            _LOGGER.debug("WS 收到: %s", plain[:200])
            return json.loads(plain)
        except Exception:  # noqa: BLE001
            return None
    return None


def _send_sync(
    api: Any, device_id: str, command: bytes, timeout: float = DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """完整的一问一答会话（同步）。异常统一按 RuntimeError 抛出."""
    info = _ws_address(api)
    addr = info["websocketAddress"]
    ws_token = info["websocketToken"]
    aes_key = info["websocketAesKey"]

    payload = {
        "content": command.hex(),
        "deviceId": device_id,
        "deviceType": WS_DEVICE_TYPE,
        "operateId": str(uuid.uuid4()),
        "target": 2,
        "ts": int(time.time() * 1000),
    }
    frame = encrypt_frame(aes_key, json.dumps(payload, separators=(",", ":")))

    try:
        from websockets.sync.client import connect  # noqa: F401
    except ImportError:
        # 老版本 websockets 没有同步客户端；executor 线程里没有运行中的事件循环，
        # 可以安全地另起一个。
        return asyncio.run(_session_async(addr, ws_token, aes_key, frame, timeout))

    with _connect(addr) as ws:
        auth = {
            "operateId": 10000000,
            "handshakeToken": ws_token,
            "ts": int(time.time() * 1000),
        }
        ws.send(json.dumps(auth))
        try:
            ack = ws.recv(timeout=6)
            _LOGGER.debug("WS 鉴权响应: %s", str(ack)[:120])
        except TimeoutError:
            _LOGGER.warning("WS 鉴权无响应，继续尝试发送")

        ws.send(frame)
        _LOGGER.debug("已发送控制包 %s", payload["content"])

        # 等待 ack / 状态推送
        for _ in range(3):
            try:
                msg = ws.recv(timeout=timeout)
            except TimeoutError:
                break
            parsed = _parse_message(aes_key, msg)
            if parsed is not None:
                return parsed

    return {"ok": True, "note": "命令已发送，无显式 ack"}


# ---------------------------------------------------------------- 高层控制
async def send_command(
    api: Any,
    device_id: str,
    command: bytes,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """通过 WebSocket 下发一条控制命令（网络阻塞部分放入 executor）.

    api 需要有 `session` 与 `base_url`（HiiggeApi 实例）。
    返回服务端 ack 的 JSON。
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _send_sync, api, device_id, command, timeout)
