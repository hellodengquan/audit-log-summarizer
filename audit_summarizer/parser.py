"""日志解析模块：将结构化/半结构化日志统一映射为标准字段。

标准字段：
    ts       - float, Unix 时间戳（秒）
    subject  - str, 行为主体（用户/IP/服务账号等）
    action   - str, 动作类型（login/delete/deploy/read/write/...）
    resource - str, 被操作资源（路径/表名/API 端点等）
    status   - str, 结果状态（success/failure/warn/... 或 HTTP 状态码）
    raw      - str, 原始行（调试用）
"""

from __future__ import annotations

import re
import json
import csv
import os
from datetime import datetime, timezone
from typing import Iterator, Dict, Any, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 时间解析：覆盖常见格式
# ---------------------------------------------------------------------------

_TS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"), "iso"),
    (re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*)\]"), "nginx"),
    (re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "syslog"),
    (re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"), "slash"),
]

_DATETIME_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
]

_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_timestamp(text: str, hint_year: Optional[int] = None) -> Optional[float]:
    """从任意文本中尝试解析时间戳，失败返回 None。"""
    if not text:
        return None

    pure = re.match(r"^\d{10}(\.\d+)?$", text)
    if pure:
        return float(text)

    pure_ms = re.match(r"^\d{13}$", text)
    if pure_ms:
        return int(text) / 1000.0

    for regex, _kind in _TS_PATTERNS:
        m = regex.search(text)
        if not m:
            continue
        candidate = m.group(1).replace(",", ".")
        t = _try_parse_formats(candidate, hint_year)
        if t is not None:
            return t

    for fmt in _DATETIME_FORMATS:
        t = _try_strptime(text.strip(), fmt, hint_year)
        if t is not None:
            return t

    return None


def _try_parse_formats(s: str, hint_year: Optional[int]) -> Optional[float]:
    for fmt in _DATETIME_FORMATS:
        t = _try_strptime(s, fmt, hint_year)
        if t is not None:
            return t
    return None


def _try_strptime(s: str, fmt: str, hint_year: Optional[int]) -> Optional[float]:
    try:
        dt = datetime.strptime(s, fmt)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
        if hint_year and dt.year == 1900:
            dt = dt.replace(year=hint_year)
    return dt.timestamp()


# ---------------------------------------------------------------------------
# 主体/动作推断：基于关键词与正则
# ---------------------------------------------------------------------------

_SUBJECT_HINTS = ["user", "username", "account", "uid", "client_ip", "client", "src_ip", "src", "remote_addr", "host"]
_ACTION_HINTS = ["action", "event", "method", "op", "operation", "cmd", "command", "type"]
_RESOURCE_HINTS = ["resource", "path", "url", "uri", "endpoint", "table", "object", "target", "file"]
_STATUS_HINTS = ["status", "result", "level", "code", "response_code", "http_status"]

_SUCCESS_WORDS = {"success", "ok", "succeed", "succeeded", "passed", "allowed", "accepted", "200", "201", "204", "301", "302", "304"}
_FAILURE_WORDS = {"failure", "fail", "failed", "denied", "deny", "rejected", "error", "err", "forbidden", "unauthorized", "400", "401", "403", "404", "409", "500", "502", "503", "504"}
_WARN_WORDS = {"warn", "warning", "notice"}

_ACTION_KEYWORDS = [
    ("login", [r"\blog(?:ged)?[_ ]?in\b", r"\bsign[_ ]?in\b", r"\bauth(?:enticate)?\b"]),
    ("logout", [r"\blog(?:ged)?[_ ]?out\b", r"\bsign[_ ]?out\b"]),
    ("read", [r"\bread\b", r"\bview\b", r"\bget\b", r"\bselect\b", r"\blist\b", r"\bfetch\b", r"\bquery\b", r"\bsearch\b"]),
    ("write", [r"\bwrite\b", r"\bupdate\b", r"\bput\b", r"\bedit\b", r"\bmodify\b", r"\bchange\b"]),
    ("create", [r"\bcreate\b", r"\bpost\b", r"\badd\b", r"\binsert\b", r"\bnew\b", r"\bregister\b", r"\bupload\b"]),
    ("delete", [r"\bdelete\b", r"\bdrop\b", r"\bremove\b", r"\berase\b", r"\bpatch\b"]),
    ("deploy", [r"\bdeploy\b", r"\brelease\b", r"\bpublish\b", r"\brollout\b"]),
    ("restart", [r"\brestart\b", r"\breboot\b", r"\breload\b", r"\bstart\b", r"\bstop\b"]),
    ("config_change", [r"\bconfig\b", r"\bsetting\b", r"\bpolicy\b", r"\bpermission\b", r"\bgrant\b", r"\brevoke\b"]),
    ("backup", [r"\bbackup\b", r"\bdump\b", r"\bsnapshot\b"]),
    ("ssh", [r"\bssh\b"]),
    ("sudo", [r"\bsudo\b", r"\bsu\b"]),
    ("download", [r"\bdownload\b", r"\bexport\b"]),
    ("api_call", [r"\bapi\b", r"\brest\b"]),
    ("password_change", [r"\bpassw(?:or)?d\b", r"\bpasswd\b"]),
]

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:user(?:name)?|account|uid)[:= ]['\"]?([A-Za-z0-9_.@\-]+)", re.IGNORECASE)
_METHOD_RE = re.compile(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s')


def _infer_status(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip().lower()
    if not s:
        return ""
    if s in _SUCCESS_WORDS:
        return "success"
    if s in _FAILURE_WORDS:
        return "failure"
    if s in _WARN_WORDS:
        return "warning"
    return s


def _infer_action_from_text(text: str, explicit: str = "") -> str:
    if explicit:
        low = explicit.strip().lower()
        if low:
            return low.replace(" ", "_")
    low_text = text.lower()
    m = _METHOD_RE.search(text)
    if m:
        method = m.group(1).upper()
        mapping = {"GET": "read", "POST": "create", "PUT": "write", "DELETE": "delete", "PATCH": "write", "HEAD": "read", "OPTIONS": "read"}
        return mapping.get(method, f"http_{method.lower()}")
    for action, patterns in _ACTION_KEYWORDS:
        for p in patterns:
            if re.search(p, low_text):
                return action
    return "other"


def _pick(d: Dict[str, Any], keys: List[str]) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    for dk, dv in d.items():
        lk = dk.lower()
        for k in keys:
            if k in lk and dv not in (None, ""):
                return dv
    return None


def _flatten_dict(d: Dict[str, Any], prefix: str = "", sep: str = ".") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{sep}{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten_dict(v, key, sep))
        else:
            out[key] = v
    return out


def _normalize_record(raw: Dict[str, Any], source_file: str, raw_text: str, hint_year: Optional[int]) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    flat = _flatten_dict(raw)

    ts_raw = _pick(flat, ["ts", "timestamp", "time", "@timestamp", "datetime", "date", "created_at", "log_time"])
    ts: Optional[float] = None
    if ts_raw is not None:
        if isinstance(ts_raw, (int, float)):
            v = float(ts_raw)
            ts = v / 1000.0 if v > 1e12 else v
        else:
            ts = parse_timestamp(str(ts_raw), hint_year)
    if ts is None:
        ts = parse_timestamp(raw_text, hint_year)
    if ts is None:
        return None

    subject = _pick(flat, _SUBJECT_HINTS)
    if subject in (None, ""):
        m = _USER_RE.search(raw_text)
        subject = m.group(1) if m else None
    if subject in (None, ""):
        m = _IPV4_RE.search(raw_text)
        subject = m.group(0) if m else "unknown"
    subject = str(subject).strip()

    action_explicit = _pick(flat, _ACTION_HINTS) or ""
    action = _infer_action_from_text(raw_text, str(action_explicit))

    resource = _pick(flat, _RESOURCE_HINTS) or ""
    if not resource:
        from_path = re.search(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)', raw_text)
        if from_path:
            resource = from_path.group(1)
    resource = str(resource).strip()

    status_raw = _pick(flat, _STATUS_HINTS)
    status = _infer_status(status_raw)
    if not status:
        low = raw_text.lower()
        if any(re.search(p, low) for p in [r"\berr(?:or)?\b", r"\bfail(?:ed|ure)?\b", r"\bden(?:y|ied)\b"]):
            status = "failure"
        elif any(re.search(p, low) for p in [r"\bsuccess(?:ful)?\b", r"\bok\b", r"\bpassed\b"]):
            status = "success"
        elif re.search(r"\bwarn(?:ing)?\b", low):
            status = "warning"

    return {
        "ts": ts,
        "subject": subject,
        "action": action,
        "resource": resource[:500],
        "status": status,
        "source_file": os.path.basename(source_file),
        "raw": raw_text[:2000],
    }


# ---------------------------------------------------------------------------
# 各格式解析器
# ---------------------------------------------------------------------------

_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s"\']+)')
_PB_FIELD_RE = re.compile(r'^(\w+)\s*:\s*(.+?)\s*$')
_PB_MSG_OPEN_RE = re.compile(r'^(\w+)\s*\{')


def _detect_format(path: str, first_line: str) -> str:
    from .config import get_config
    cfg = get_config()

    overrides = cfg.format_overrides
    if overrides:
        ext = os.path.splitext(path)[1].lower()
        for pattern, fmt in overrides.items():
            if ext == pattern or ext == pattern.lower():
                return fmt

    ext = os.path.splitext(path)[1].lower()
    if ext in (".jsonl", ".ndjson"):
        return "jsonl"
    if ext == ".json":
        return "json_array" if first_line.lstrip().startswith("[") else "jsonl"
    if ext == ".csv":
        return "csv"
    if ext in (".kv", ".logfmt"):
        return "kv"
    if ext in (".pbtxt", ".textproto", ".pb.text"):
        return "protobuf"
    stripped = first_line.strip()
    if stripped.startswith("{"):
        return "jsonl"
    if stripped.startswith("["):
        return "json_array"
    kv_matches = _KV_RE.findall(stripped)
    if len(kv_matches) >= 3:
        non_ts = [k for k, _ in kv_matches if k.lower() not in ("ts", "timestamp", "time")]
        if non_ts:
            return "kv"
    if _PB_FIELD_RE.match(stripped) or _PB_MSG_OPEN_RE.match(stripped):
        return "protobuf"
    if "," in stripped and re.match(r"^[A-Za-z0-9_\s\"'\-.,:]+$", stripped[:200]):
        return "csv"
    return "text"


def parse_file(path: str, hint_year: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """解析单个日志文件，按格式自动分流。"""
    if hint_year is None:
        try:
            hint_year = datetime.fromtimestamp(os.path.getmtime(path)).year
        except OSError:
            hint_year = datetime.now().year

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = [line.rstrip("\n") for line in fh if line.strip()]
    if not lines:
        return

    fmt = _detect_format(path, lines[0])
    yield from _PARSERS[fmt](lines, path, hint_year)


def _parse_jsonl(lines: List[str], source: str, hint_year: Optional[int]) -> Iterator[Dict[str, Any]]:
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            rec = _parse_text_line(line, source, hint_year)
            if rec:
                yield rec
            continue
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    rec = _normalize_record(item, source, json.dumps(item, ensure_ascii=False), hint_year)
                    if rec:
                        yield rec
        elif isinstance(obj, dict):
            rec = _normalize_record(obj, source, line, hint_year)
            if rec:
                yield rec


def _parse_json_array(lines: List[str], source: str, hint_year: Optional[int]) -> Iterator[Dict[str, Any]]:
    blob = "".join(lines)
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        yield from _parse_jsonl(lines, source, hint_year)
        return
    if not isinstance(data, list):
        data = [data]
    for item in data:
        if isinstance(item, dict):
            rec = _normalize_record(item, source, json.dumps(item, ensure_ascii=False), hint_year)
            if rec:
                yield rec


def _parse_csv(lines: List[str], source: str, hint_year: Optional[int]) -> Iterator[Dict[str, Any]]:
    reader = csv.DictReader(lines)
    for row in reader:
        rec = _normalize_record(row, source, ",".join(f"{k}={v}" for k, v in row.items()), hint_year)
        if rec:
            yield rec


def _parse_text_line(line: str, source: str, hint_year: Optional[int]) -> Optional[Dict[str, Any]]:
    kv_match = dict(re.findall(r"(\w+)=['\"]?([^'\"]+?)['\"]?(?=\s+\w+=|$)", line))
    if len(kv_match) >= 3:
        return _normalize_record(kv_match, source, line, hint_year)
    fields = re.split(r"[\s|,\t]+", line, maxsplit=0)
    if len(fields) >= 3:
        loose = {f"f{i}": f for i, f in enumerate(fields)}
        rec = _normalize_record(loose, source, line, hint_year)
        if rec:
            rec["action"] = _infer_action_from_text(line, "")
            return rec
    ts = parse_timestamp(line, hint_year)
    if ts is None:
        return None
    m_user = _USER_RE.search(line)
    m_ip = _IPV4_RE.search(line)
    subject = m_user.group(1) if m_user else (m_ip.group(0) if m_ip else "unknown")
    return {
        "ts": ts,
        "subject": subject,
        "action": _infer_action_from_text(line, ""),
        "resource": "",
        "status": _infer_status_from_text(line),
        "source_file": os.path.basename(source),
        "raw": line[:2000],
    }


def _infer_status_from_text(text: str) -> str:
    low = text.lower()
    if any(re.search(p, low) for p in [r"\berr(?:or)?\b", r"\bfail(?:ed|ure)?\b", r"\bden(?:y|ied)\b"]):
        return "failure"
    if any(re.search(p, low) for p in [r"\bsuccess(?:ful)?\b", r"\bok\b", r"\bpassed\b"]):
        return "success"
    if re.search(r"\bwarn(?:ing)?\b", low):
        return "warning"
    return ""


def _parse_kv(lines: List[str], source: str, hint_year: Optional[int]) -> Iterator[Dict[str, Any]]:
    """解析 key=value 格式（logfmt / Bro/Zeek 等）。"""
    for line in lines:
        pairs = _KV_RE.findall(line)
        if len(pairs) < 2:
            rec = _parse_text_line(line, source, hint_year)
            if rec:
                yield rec
            continue
        d: Dict[str, Any] = {}
        for k, v in pairs:
            if v.startswith('"') and v.endswith('"') and len(v) >= 2:
                v = v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
            d[k] = v
        rec = _normalize_record(d, source, line, hint_year)
        if rec:
            yield rec


def _parse_protobuf(lines: List[str], source: str, hint_year: Optional[int]) -> Iterator[Dict[str, Any]]:
    """解析 protobuf text-format 日志，支持多版本 schema。

    两种常见形态：
    A) 单行平铺：  field1: val1  field2: val2  field3 { sub: val }
    B) 多行消息：  message_type { field1: val ... }

    schema 版本选择：
    1. 消息块中含 schema_version 字段时，使用指定版本
    2. 否则使用 audit.yaml 中 protobuf_default_version 配置
    """
    msg_blocks: List[str] = []
    cur_block: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if cur_block:
                msg_blocks.append("\n".join(cur_block))
                cur_block = []
            continue
        cur_block.append(stripped)
    if cur_block:
        msg_blocks.append("\n".join(cur_block))

    for block in msg_blocks:
        d: Dict[str, Any] = {}
        for m in _PB_FIELD_RE.finditer(block):
            key = m.group(1)
            val = m.group(2).strip().strip('"')
            if key in d:
                existing = d[key]
                if isinstance(existing, list):
                    existing.append(val)
                else:
                    d[key] = [existing, val]
            else:
                d[key] = val
        for m in _PB_MSG_OPEN_RE.finditer(block):
            msg_type = m.group(1)
            if "message_type" not in d:
                d["message_type"] = msg_type

        version = d.get("schema_version") if isinstance(d.get("schema_version"), str) else None
        log_field_set = set(d.keys()) if d else None
        field_mappings = _get_pb_schema_mappings(version, log_field_set)

        if field_mappings:
            mapped: Dict[str, Any] = {}
            for k, v in d.items():
                canonical = field_mappings.get(k, k)
                if canonical in mapped:
                    if isinstance(mapped[canonical], list):
                        mapped[canonical].append(v)
                    else:
                        mapped[canonical] = [mapped[canonical], v]
                else:
                    mapped[canonical] = v
            d = mapped

        if not d:
            rec = _parse_text_line(block.split("\n")[0], source, hint_year)
            if rec:
                yield rec
            continue
        rec = _normalize_record(d, source, block[:2000], hint_year)
        if rec:
            yield rec


def _load_pb_schema(path: str) -> Dict[str, str]:
    """加载 protobuf schema 描述文件，返回 {proto_field: canonical_name} 映射。

    支持简单的 proto 描述格式，每行一个映射：
      proto_field_name -> canonical_name
    或纯 proto 文件（自动提取字段名 -> 小写下划线名）。
    支持元信息注释:
      # version: v1
    """
    mappings: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue
                arrow_match = re.match(r'(\w+)\s*->\s*(\w+)', stripped)
                if arrow_match:
                    mappings[arrow_match.group(1)] = arrow_match.group(2)
                    continue
                proto_field = re.match(r'^\s*(\w+)\s+\w+\s*=\s*\d+', stripped)
                if proto_field:
                    field_name = proto_field.group(1)
                    mappings[field_name] = re.sub(r'([A-Z])', r'_\1', field_name).lower().lstrip('_')
    except OSError:
        pass
    return mappings


_PB_SCHEMA_CACHE: Dict[str, Dict[str, str]] = {}
_PB_COMPAT_MATRIX: Optional[Dict[str, Dict[str, float]]] = None


def _build_compat_matrix(schemas: Dict[str, str]) -> Dict[str, Dict[str, float]]:
    """根据已加载 schema 构建版本兼容性矩阵。

    兼容度 = 两版本共有字段数 / 源版本字段总数。
    矩阵为 {v_from: {v_to: compat_ratio}}，1.0 表示完全兼容。
    """
    field_sets: Dict[str, set] = {}
    for ver, path in schemas.items():
        mappings = _PB_SCHEMA_CACHE.get(path)
        if mappings is None:
            mappings = _load_pb_schema(path)
            _PB_SCHEMA_CACHE[path] = mappings
        field_sets[ver] = set(mappings.keys())

    matrix: Dict[str, Dict[str, float]] = {}
    for v_from, fs_from in field_sets.items():
        matrix[v_from] = {}
        for v_to, fs_to in field_sets.items():
            if not fs_from:
                matrix[v_from][v_to] = 0.0
            else:
                matrix[v_from][v_to] = len(fs_from & fs_to) / len(fs_from)
    return matrix


def _get_compat_matrix() -> Dict[str, Dict[str, float]]:
    """获取兼容性矩阵（惰性构建）。"""
    global _PB_COMPAT_MATRIX
    if _PB_COMPAT_MATRIX is not None:
        return _PB_COMPAT_MATRIX
    from .config import get_config
    cfg = get_config()
    schemas = cfg.protobuf_schemas
    if len(schemas) < 2:
        _PB_COMPAT_MATRIX = {}
        return {}
    _PB_COMPAT_MATRIX = _build_compat_matrix(schemas)
    return _PB_COMPAT_MATRIX


def _resolve_schema_version(requested: Optional[str], log_fields: Optional[set] = None) -> Optional[str]:
    """根据请求版本和日志字段自动选择最佳 schema 版本。

    选择策略：
    1. 精确匹配：请求版本存在于已注册 schema 中
    2. 字段匹配：日志实际字段与某版本 schema 字段交集率最高
    3. 兼容回退：按兼容性矩阵降级到最兼容版本
    4. 默认版本
    """
    from .config import get_config
    cfg = get_config()
    schemas = cfg.protobuf_schemas
    if not schemas:
        return None

    if requested and requested in schemas:
        return requested

    if log_fields:
        best_ver = None
        best_score = 0.0
        for ver, path in schemas.items():
            mappings = _PB_SCHEMA_CACHE.get(path)
            if mappings is None:
                mappings = _load_pb_schema(path)
                _PB_SCHEMA_CACHE[path] = mappings
            schema_fields = set(mappings.keys())
            if not schema_fields:
                continue
            score = len(log_fields & schema_fields) / len(schema_fields)
            if score > best_score:
                best_score = score
                best_ver = ver
        if best_ver and best_score > 0.3:
            return best_ver

    matrix = _get_compat_matrix()
    if requested and requested in matrix:
        candidates = [(v, score) for v, score in matrix[requested].items() if v != requested and score > 0]
        candidates.sort(key=lambda x: x[1], reverse=True)
        if candidates:
            return candidates[0][0]

    default = cfg.protobuf_default_version
    if default in schemas:
        return default

    return next(iter(schemas))


def _get_pb_schema_mappings(version: Optional[str] = None, log_fields: Optional[set] = None) -> Dict[str, str]:
    """根据版本获取 protobuf schema 字段映射，支持兼容性自动选版本。

    Args:
        version: 日志中声明的 schema 版本
        log_fields: 日志中实际出现的字段名集合，用于自动匹配

    Returns:
        {proto_field: canonical_name} 映射，无配置时返回空 dict
    """
    from .config import get_config
    cfg = get_config()
    schemas = cfg.protobuf_schemas
    if not schemas:
        return {}

    resolved = _resolve_schema_version(version, log_fields)
    if not resolved:
        return {}

    schema_path = schemas.get(resolved)
    if not schema_path or not os.path.exists(schema_path):
        return {}

    if schema_path in _PB_SCHEMA_CACHE:
        return _PB_SCHEMA_CACHE[schema_path]

    mappings = _load_pb_schema(schema_path)
    _PB_SCHEMA_CACHE[schema_path] = mappings
    return mappings


def _invalidate_pb_schema_cache() -> None:
    """清空 protobuf schema 缓存和兼容性矩阵（/admin/reload 时调用）。"""
    global _PB_COMPAT_MATRIX
    _PB_SCHEMA_CACHE.clear()
    _PB_COMPAT_MATRIX = None


def _parse_text(lines: List[str], source: str, hint_year: Optional[int]) -> Iterator[Dict[str, Any]]:
    for line in lines:
        rec = _parse_text_line(line, source, hint_year)
        if rec:
            yield rec


_PARSERS = {
    "jsonl": _parse_jsonl,
    "json_array": _parse_json_array,
    "csv": _parse_csv,
    "kv": _parse_kv,
    "protobuf": _parse_protobuf,
    "text": _parse_text,
}
