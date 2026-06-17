"""配置加载模块：解析 audit.yaml，提供全局单例访问。

仅依赖 Python 标准库，内建轻量 YAML 子集解析器。
支持标量、列表、字典、嵌套结构，不支持锚点/引用/多文档。
"""

from __future__ import annotations

import copy
import os
import re
from typing import Any, Dict, List, Optional, Tuple


_DEFAULTS: Dict[str, Any] = {
    "parser": {
        "protobuf_schema_path": "",
        "format_overrides": {},
    },
    "analyzer": {
        "spike_tiers": {
            "5min": 300,
            "1h": 3600,
            "24h": 86400,
        },
        "spike_z_threshold": 2.5,
        "dynamic_bulk": True,
        "subject_categories": {
            "human": {
                "prefixes": ["user", "admin", "operator", "ops_", "root", "test"],
                "bulk_threshold": {
                    "max_window_seconds": 600,
                    "min_count_base": 3,
                    "min_count_ratio": 0.01,
                    "rate_factor": 0.5,
                },
            },
            "service": {
                "prefixes": ["svc_", "service", "cron", "daemon", "system", "agent_", "bot_"],
                "bulk_threshold": {
                    "max_window_seconds": 300,
                    "min_count_base": 15,
                    "min_count_ratio": 0.03,
                    "rate_factor": 2.0,
                },
            },
            "ip": {
                "prefixes": [],
                "bulk_threshold": {
                    "max_window_seconds": 300,
                    "min_count_base": 8,
                    "min_count_ratio": 0.02,
                    "rate_factor": 1.0,
                },
            },
        },
    },
    "output": {
        "default_page_size": 0,
        "default_sort_by": "count",
        "default_sort_order": "desc",
    },
    "storage": {
        "ttl_days": None,
        "table_prefix": "logs_",
        "unified_view_name": "audit_unified_view",
    },
    "admin": {
        "reload_port": 0,
        "reload_host": "127.0.0.1",
    },
}

_INSTANCE: Optional["AuditConfig"] = None


# ---------------------------------------------------------------------------
# 轻量 YAML 子集解析器
# ---------------------------------------------------------------------------

def _parse_yaml(text: str) -> Dict[str, Any]:
    """解析 YAML 子集文本为 dict。支持缩进嵌套、列表、行内值。"""
    lines = text.split("\n")
    root: Dict[str, Any] = {}
    stack: List[Tuple[Any, int]] = [(root, -1)]

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip())

        while stack and indent <= stack[-1][1]:
            stack.pop()

        if stripped.startswith("- "):
            item_content = stripped[2:].strip()
            container, _ = stack[-1]

            if isinstance(container, dict) and not container and len(stack) >= 2:
                parent, parent_indent = stack[-2]
                if isinstance(parent, dict) and parent:
                    pkey = list(parent.keys())[-1]
                    parent[pkey] = []
                    stack.pop()
                    stack.append((parent[pkey], parent_indent))

            container, _ = stack[-1]
            last_key = None
            target = container

            if isinstance(container, dict) and container:
                last_key = list(container.keys())[-1]
                target = container[last_key]
                if isinstance(target, dict) and not target:
                    container[last_key] = []
                    target = container[last_key]
                    stack[-1] = (target, stack[-1][1])

            if ":" in item_content:
                colon_pos = item_content.index(":")
                ik = item_content[:colon_pos].strip()
                iv = item_content[colon_pos + 1:].strip()
                item_dict = {ik: _parse_scalar(iv)}

                if isinstance(target, list):
                    target.append(item_dict)
                    stack.append((item_dict, indent))
                elif isinstance(container, dict) and last_key:
                    container[last_key] = [item_dict]
                    stack.append((item_dict, indent))
                elif isinstance(container, list):
                    container.append(item_dict)
                    stack.append((item_dict, indent))
            else:
                item_val = _parse_scalar(item_content)
                if isinstance(target, list):
                    target.append(item_val)
                elif isinstance(container, dict) and last_key:
                    container[last_key] = [item_val]
                elif isinstance(container, list):
                    container.append(item_val)

        elif ":" in stripped:
            colon_pos = stripped.index(":")
            key = stripped[:colon_pos].strip()
            after = stripped[colon_pos + 1:].strip()

            if after == "" or after.startswith("#"):
                new_dict: Dict[str, Any] = {}
                container, _ = stack[-1]
                if isinstance(container, dict):
                    container[key] = new_dict
                    stack.append((new_dict, indent))
                elif isinstance(container, list):
                    if isinstance(container[-1], dict):
                        container[-1][key] = new_dict
                        stack.append((new_dict, indent))
                    else:
                        entry = {key: new_dict}
                        container.append(entry)
                        stack.append((new_dict, indent))
            else:
                val = _parse_scalar(after)
                container, _ = stack[-1]
                if isinstance(container, dict):
                    container[key] = val
                elif isinstance(container, list):
                    if isinstance(container[-1], dict):
                        container[-1][key] = val

    return root


def _parse_scalar(s: str) -> Any:
    if not s:
        return ""
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return s[1:-1].replace('\\"', '"').replace("\\n", "\n")
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1].replace("''", "'")
    low = s.lower()
    if low in ("null", "~", ""):
        return None
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    if s == "{}":
        return {}
    if s == "[]":
        return []
    return s


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


class AuditConfig:
    """审计工具全局配置。"""

    def __init__(self, data: Dict[str, Any], config_path: Optional[str] = None):
        self._data = data
        self.config_path = config_path

    def get(self, *keys: str, default: Any = None) -> Any:
        node = self._data
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

    @property
    def protobuf_schema_path(self) -> str:
        path = self.get("parser", "protobuf_schema_path", default="")
        if path and self.config_path and not os.path.isabs(path):
            base = os.path.dirname(os.path.abspath(self.config_path))
            path = os.path.join(base, path)
        return path

    @property
    def spike_tiers(self) -> Dict[str, int]:
        return self.get("analyzer", "spike_tiers", default=_DEFAULTS["analyzer"]["spike_tiers"])

    @property
    def spike_tiers_seconds(self) -> List[int]:
        tiers = self.spike_tiers
        if isinstance(tiers, dict):
            return list(tiers.values())
        return []

    @property
    def spike_z_threshold(self) -> float:
        return self.get("analyzer", "spike_z_threshold", default=2.5)

    @property
    def dynamic_bulk(self) -> bool:
        return self.get("analyzer", "dynamic_bulk", default=True)

    @property
    def subject_categories(self) -> Dict[str, Any]:
        return self.get("analyzer", "subject_categories", default=_DEFAULTS["analyzer"]["subject_categories"])

    @property
    def default_page_size(self) -> int:
        return self.get("output", "default_page_size", default=0)

    @property
    def default_sort_by(self) -> str:
        return self.get("output", "default_sort_by", default="count")

    @property
    def default_sort_order(self) -> str:
        return self.get("output", "default_sort_order", default="desc")

    @property
    def ttl_days(self) -> Optional[int]:
        return self.get("storage", "ttl_days", default=None)

    @property
    def table_prefix(self) -> str:
        return self.get("storage", "table_prefix", default="logs_")

    @property
    def unified_view_name(self) -> str:
        return self.get("storage", "unified_view_name", default="audit_unified_view")

    @property
    def reload_port(self) -> int:
        return self.get("admin", "reload_port", default=0)

    @property
    def reload_host(self) -> str:
        return self.get("admin", "reload_host", default="127.0.0.1")

    @property
    def format_overrides(self) -> Dict[str, str]:
        return self.get("parser", "format_overrides", default={})

    def reload(self) -> None:
        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as fh:
                raw = _parse_yaml(fh.read())
            merged = _deep_merge(_DEFAULTS, raw)
            self._data = merged

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)


def load_config(path: Optional[str] = None) -> AuditConfig:
    global _INSTANCE
    if path is None:
        candidates = [
            os.path.join(os.getcwd(), "audit.yaml"),
            os.path.join(os.path.dirname(__file__), "..", "audit.yaml"),
        ]
        for c in candidates:
            if os.path.exists(c):
                path = c
                break

    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            raw = _parse_yaml(fh.read())
        merged = _deep_merge(_DEFAULTS, raw)
    else:
        merged = copy.deepcopy(_DEFAULTS)

    cfg = AuditConfig(merged, config_path=path)
    _INSTANCE = cfg
    return cfg


def get_config() -> AuditConfig:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = load_config()
    return _INSTANCE


def set_config(cfg: AuditConfig) -> None:
    global _INSTANCE
    _INSTANCE = cfg
