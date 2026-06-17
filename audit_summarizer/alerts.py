"""告警模块：运维可观测性增强。

当前功能：
1. page_size 超过 max_page_size 告警（支持抑制窗口、Webhook 通知）
2. 其他告警可复用此框架（Pub/Sub backend 切换、物化表刷新失败等）

仅依赖标准库，Webhook 是可选通道（没配置时只打 stderr 日志）。
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


@dataclass
class AlertEvent:
    """告警事件。"""

    alert_type: str
    severity: str
    title: str
    detail: str
    context: Dict[str, Any]
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "context": self.context,
            "timestamp": self.timestamp,
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)),
        }

    def to_stderr_text(self) -> str:
        return "[告警] {sev} [{typ}] {title}: {detail}".format(
            sev=self.severity.upper(),
            typ=self.alert_type,
            title=self.title,
            detail=self.detail,
        )


class AlertManager:
    """告警管理器：去重、抑制、多通道分发。

    单例模式，通过 get_alert_manager() 获取。
    """

    _instance: Optional["AlertManager"] = None
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "AlertManager":
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._suppress_map: Dict[str, float] = {}
        self._history: List[AlertEvent] = []
        self._max_history = 1000
        self._extra_handlers: List[Callable[[AlertEvent], None]] = []
        self._webhook_url: str = ""
        self._default_suppress_seconds: int = 300

    def configure(self,
                  webhook_url: str = "",
                  default_suppress_seconds: int = 300) -> None:
        with self._lock:
            self._webhook_url = webhook_url
            self._default_suppress_seconds = max(0, int(default_suppress_seconds))

    def add_handler(self, handler: Callable[[AlertEvent], None]) -> None:
        """注册自定义告警处理函数（如发送到监控系统）。"""
        with self._lock:
            self._extra_handlers.append(handler)

    def _should_suppress(self, dedupe_key: str, suppress_seconds: int) -> bool:
        now = time.time()
        last_ts = self._suppress_map.get(dedupe_key, 0.0)
        if last_ts + suppress_seconds > now:
            return True
        self._suppress_map[dedupe_key] = now
        return False

    def emit(self,
             alert_type: str,
             title: str,
             detail: str,
             severity: str = "warning",
             context: Optional[Dict[str, Any]] = None,
             suppress_seconds: Optional[int] = None,
             dedupe_key: Optional[str] = None) -> Optional[AlertEvent]:
        """发出告警，返回实际发送的事件（被抑制时返回 None）。"""

        suppress = suppress_seconds if suppress_seconds is not None else self._default_suppress_seconds
        key = dedupe_key or alert_type

        with self._lock:
            if suppress > 0 and self._should_suppress(key, suppress):
                return None

            event = AlertEvent(
                alert_type=alert_type,
                severity=severity,
                title=title,
                detail=detail,
                context=context or {},
                timestamp=time.time(),
            )

            self._history.append(event)
            if len(self._history) > self._max_history:
                drop_count = len(self._history) - self._max_history
                self._history = self._history[drop_count:]

            handlers_snapshot = list(self._extra_handlers)
            webhook_url = self._webhook_url

        sys.stderr.write(event.to_stderr_text() + "\n")
        sys.stderr.flush()

        for h in handlers_snapshot:
            try:
                h(event)
            except Exception:
                pass

        if webhook_url:
            self._fire_webhook(event, webhook_url)

        return event

    def _fire_webhook(self, event: AlertEvent, url: str) -> None:
        def _send():
            try:
                payload = json.dumps(event.to_dict()).encode()
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3):
                    pass
            except (urllib.error.URLError, OSError):
                pass

        threading.Thread(target=_send, daemon=True).start()

    def recent_alerts(self, since_ts: Optional[float] = None) -> List[Dict[str, Any]]:
        with self._lock:
            events = self._history
            if since_ts is not None:
                events = [e for e in events if e.timestamp >= since_ts]
            return [e.to_dict() for e in events]


def get_alert_manager() -> AlertManager:
    """获取告警管理器单例。"""
    return AlertManager.get_instance()


def alert_page_size_exceeded(
    requested: int,
    max_page_size: int,
    actual: int,
    source: str = "cli",
) -> Optional[AlertEvent]:
    """发出 page_size 超限告警（去重窗口内仅发一次）。

    Args:
        requested: 用户请求的 page_size
        max_page_size: 配置的上限
        actual: 实际生效的 page_size（截断后）
        source: 触发来源（cli / api）
    """
    mgr = get_alert_manager()

    from .config import get_config
    cfg = get_config()
    mgr.configure(
        webhook_url=cfg.page_size_alert_webhook,
        default_suppress_seconds=cfg.page_size_alert_suppress_seconds,
    )

    pid = os.getpid()
    dedupe_key = f"page_size_exceeded:{pid}"
    return mgr.emit(
        alert_type="page_size_exceeded",
        title="分页请求超上限被截断",
        detail=(
            f"请求 page_size={requested} 超过配置 max_page_size={max_page_size}，"
            f"已自动截断为 {actual}"
        ),
        severity="warning",
        context={
            "requested": requested,
            "max_page_size": max_page_size,
            "actual": actual,
            "source": source,
            "pid": pid,
        },
        dedupe_key=dedupe_key,
    )
