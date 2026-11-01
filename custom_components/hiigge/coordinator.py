"""Hiigge 云端轮询协调器（单设备）.

每轮拉三个接口：

    getDeviceInfo           → 设备静态信息（名称/型号/固件/SN/IP/最后在线）
    getHiiggeDeviceStatus   → dataHexStr（protobuf），解码成状态字典
    getHomeTodayDrinkData   → 今日喝水次数与分时明细（家庭维度）

签名由 `api._body()` 按当前时间现算，所以可以长期无人工干预运行
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import (
    HiiggeApi,
    HiiggeAuthError,
    HiiggeDevice,
    HiiggeError,
    HiiggeSignatureError,
    summarize_today_drink,
)
from .catalog import DEFAULT_SMART_TYPE
from .const import DOMAIN
from .ws import send_command

_LOGGER = logging.getLogger(__name__)

# 下发命令后按这些时间点（秒，相对上一次）去回读状态，直到设备上报的值
# 与期望一致为止。设备执行命令到上报云端有几秒延迟，稀疏的单次回读容易落空。
CONFIRM_DELAYS: tuple[float, ...] = (2.0, 6.0, 16.0, 35.0)

# 期望状态的抑制窗口上限：超过这个时间设备仍未上报期望值，就认账回退。
CONFIRM_TIMEOUT = 90.0

# 读取期望值的哨兵：区分「没有期望值」与「期望值就是 None」
MISSING = object()


@dataclass
class HiiggeSnapshot:
    devices: list[HiiggeDevice]

    def by_id(self, device_id: str) -> HiiggeDevice | None:
        for dev in self.devices:
            if dev.device_id == device_id:
                return dev
        return None


class HiiggeCoordinator(DataUpdateCoordinator[HiiggeSnapshot]):
    def __init__(
        self,
        hass: HomeAssistant,
        api: HiiggeApi,
        device_id: str,
        scan_interval: int,
        smart_type: int = DEFAULT_SMART_TYPE,
        home_id: str | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.api = api
        self.device_id = device_id
        self.smart_type = smart_type
        # 喝水统计是家庭维度接口；老配置条目没有存 homeId，首次刷新时反查一次
        self.home_id = home_id
        # 写操作后的期望状态（见 expect_state）
        self._expected: dict[str, Any] = {}
        self._expected_deadline: float = 0.0
        self._confirm_task: asyncio.Task | None = None

    async def _async_update_data(self) -> HiiggeSnapshot:
        try:
            info = await self.api.device_info(self.device_id)
        except HiiggeSignatureError as err:
            raise UpdateFailed(f"签名被拒: {err}") from err
        except HiiggeAuthError as err:
            raise ConfigEntryAuthFailed(f"token 失效，需要重新登录: {err}") from err
        except HiiggeError as err:
            raise UpdateFailed(f"getDeviceInfo 失败: {err}") from err

        if not info:
            raise UpdateFailed("getDeviceInfo 返回空，deviceId 可能不正确")

        raw = {**info, "deviceId": info.get("deviceId") or self.device_id}

        status: dict[str, Any] = {}
        try:
            status = await self.api.device_status(raw, self.smart_type)
        except HiiggeError as err:
            _LOGGER.debug("getHiiggeDeviceStatus 失败: %s", err)

        if status:
            status.setdefault("online", True)

        status.update(await self._fetch_drink())
        # 刚下发的命令，设备可能还没把新状态上报上来：确认还在就继续用期望值压住
        self._reconcile_expected(status)
        return HiiggeSnapshot(devices=[HiiggeDevice(raw=raw, status=status)])

    async def _fetch_drink(self) -> dict[str, Any]:
        """今日喝水统计.

        失败只记 debug —— 喝水属于附加信息，不应因此把整个集成标成不可用。
        """
        if not self.home_id:
            try:
                self.home_id = await self.api.find_home_id(self.device_id)
            except HiiggeError as err:
                _LOGGER.debug("反查 homeId 失败: %s", err)
                return {}
            if not self.home_id:
                _LOGGER.debug("未找到设备 %s 所属家庭，跳过喝水统计", self.device_id)
                return {}

        now = dt_util.now()
        try:
            raw = await self.api.today_drink(self.home_id, now)
        except HiiggeError as err:
            _LOGGER.debug("getHomeTodayDrinkData 失败: %s", err)
            return {}
        if not raw:
            return {}

        info = summarize_today_drink(raw, now)
        return {
            "drink_count": info["count"],
            "drink_duration_sec": info["duration_sec"],
            "drink_avg_duration_sec": info["avg_duration_sec"],
            "drink_compare_avg": info["compare_avg"],
            "drink_last_ts": info["last_ts"],
            "drink_last_hour": info["last_hour"],
            "drink_active_hours": info["active_hours"],
            "drink_hourly": info["hourly"],
            "drink_date": f"{now.year:04d}-{now.month:02d}-{now.day:02d}",
        }

    async def async_send_command(self, command: bytes) -> dict[str, Any]:
        """下发一条 SmartPacket（走 WebSocket），随后刷新状态.

        REST 的 setUserDeviceConfig 只把配置存在云端、不下发给设备，
        因此所有控制都从这里走。

        设备收到命令后需要时间上报新状态，立即刷新通常还是旧值，
        所以延后几秒再拉一次，避免界面看起来"点了没反应"。
        没有期望状态可登记时（例如按钮类一次性动作）用这个方法。
        """
        result = await send_command(self.api, self.device_id, command)
        self.hass.async_create_task(self._refresh_later())
        return result

    async def async_apply_command(
        self, command: bytes, expect: dict[str, Any]
    ) -> dict[str, Any]:
        """下发会改变某个可读状态字段的命令，并登记该字段的期望值.

        `expect` 是「命令生效后设备应当上报的键值」，用于在设备回读之前
        用期望值占位（见 `expect_state`）。
        """
        result = await send_command(self.api, self.device_id, command)
        self.expect_state(expect)
        return result

    # -- 写后回读：抑制回弹 -------------------------------------------------
    #
    # 为什么需要这一层：设备状态是**设备主动上报**到云端的，WS 命令下发成功
    # 只代表设备收到，真正生效并上报还有几秒延迟。若下发后立刻按云端值刷新，
    # 界面会先跳回旧值（"改了又变回去"），要等下个轮询周期才变成新值。
    # 所以在收到设备回读确认前，实体读取时优先返回期望值。
    #
    # 期望值**不写进快照**：快照始终是设备真实上报的内容，期望值只在
    # `expected_value()` 里叠加。这样即使随后刷新失败、或超时，读取也会
    # 自动落回真实值，不会把未确认的状态长期留在界面上。

    def expect_state(self, values: dict[str, Any], timeout: float = CONFIRM_TIMEOUT) -> None:
        """登记一次写操作的期望状态，并立即通知实体刷新."""
        expected = {key: value for key, value in values.items() if value is not None}
        if not expected:
            return

        self._expected = expected
        self._expected_deadline = time.monotonic() + timeout
        # 让界面立刻按期望值显示，不必等下一条状态到达
        self.async_update_listeners()
        self._schedule_confirm()

    def expected_value(self, key: str) -> Any:
        """等待设备确认期间，该字段应显示的值；没有期望值时返回 MISSING."""
        if key in self._expected and time.monotonic() <= self._expected_deadline:
            return self._expected[key]
        return MISSING

    def is_pending(self, key: str) -> bool:
        """该字段是否仍在等待设备回读确认（供实体暴露诊断属性）."""
        return key in self._expected and time.monotonic() <= self._expected_deadline

    def _reconcile_expected(self, status: dict[str, Any]) -> None:
        """用刚拉到的真实状态核对期望值：已确认或已超时就撤销抑制."""
        if not self._expected:
            return

        if time.monotonic() > self._expected_deadline:
            _LOGGER.warning(
                "下发命令后 %.0fs 内设备仍未上报期望状态，回退为设备上报值：%s",
                CONFIRM_TIMEOUT,
                self._expected,
            )
            self._expected = {}
            return

        if all(status.get(key) == value for key, value in self._expected.items()):
            _LOGGER.debug("设备已回读确认写操作：%s", self._expected)
            self._expected = {}

    async def _confirm_expected(self) -> None:
        """按退避节奏回读，直到设备确认期望值或超时."""
        for delay in CONFIRM_DELAYS:
            await asyncio.sleep(delay)
            if not self._expected:
                return
            await self.async_request_refresh()

        # 退避走完仍未确认：等到超时点再拉一次，让期望值按真实状态结算
        remain = self._expected_deadline - time.monotonic()
        if self._expected and remain > 0:
            await asyncio.sleep(remain)
        if self._expected:
            await self.async_request_refresh()

    def _schedule_confirm(self) -> None:
        self._cancel_confirm_task()
        self._confirm_task = self.hass.async_create_task(self._confirm_expected())

    def _cancel_confirm_task(self) -> None:
        task = self._confirm_task
        self._confirm_task = None
        if task is not None and not task.done():
            task.cancel()

    def async_cancel_pending(self) -> None:
        """卸载集成时清掉未完成的回读任务."""
        self._expected = {}
        self._cancel_confirm_task()

    async def _refresh_later(self, delay: float = 2.5) -> None:
        await asyncio.sleep(delay)
        await self.async_request_refresh()

    async def async_set_device_config(self, configs: dict[str, Any]) -> None:
        """仅写云端配置（不下发设备），保留给需要存档类字段的场景."""
        await self.api.set_device_config(self.device_id, configs)
        await self.async_request_refresh()

    async def async_clear_water_low(self) -> None:
        raw = (
            self.data.devices[0].raw
            if self.data and self.data.devices
            else {"deviceId": self.device_id}
        )
        await self.api.clear_water_low_smart(raw, self.smart_type)
        await self.async_request_refresh()
