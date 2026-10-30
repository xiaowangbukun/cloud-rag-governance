"""敏感字段识别与脱敏规则。

原则：向量库与模型上下文中不能出现可还原项目进度、负责人身份、精确规模的原始信息。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ------------------------------------------------------------------ 正则库

# 中文语境下 \b 不可靠（汉字属于 \w），故不使用词边界锚定
RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
RE_IPV6 = re.compile(r"(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}")
RE_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
RE_CN_MOBILE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
RE_ID_CARD = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
RE_DATE = re.compile(r"(20\d{2})[-/年.](\d{1,2})[-/月.](\d{1,2})")
RE_MONTH = re.compile(r"(20\d{2})[-/年.](\d{1,2})")
RE_QUARTER = re.compile(r"(20\d{2})\s*年?\s*Q([1-4])", re.IGNORECASE)
RE_MONEY = re.compile(r"\d+(?:\.\d+)?\s*(?:元|万元|亿元|CNY|RMB|USD)", re.IGNORECASE)
RE_COST = re.compile(r"\d+(?:\.\d+)?\s*(?:元/月|每月|月度费用)")
RE_PERCENT = re.compile(r"\d+(?:\.\d+)?%")
RE_HOST = re.compile(r"(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}")
RE_ACCESS_KEY = re.compile(r"(?:AKID|AKIA|LTAI)[A-Za-z0-9]{8,}")
RE_SECRET_KEY = re.compile(r"(?i)(?:secret|password|token|api[_-]?key)\s*[:=]\s*\S+")
RE_PROJECT_CODE = re.compile(r"[A-Z]{2,6}-\d{2,6}")
RE_CN_NAME = re.compile(r"(?<![\u4e00-\u9fa5])[\u4e00-\u9fa5]{2,3}(?=(?:同事|经理|负责人|owner|Owner))")
RE_PHRASE_DATE = re.compile(
    r"(?:上线|投产|交付|发布|割接|验收|迁移|扩容)[^，。；\s]{0,4}?\s*(?:时间|日期|计划|窗口|排期)?\s*[:：]?\s*"
    r"(20\d{2})[-/年.](\d{1,2})(?:[-/月.](\d{1,2}))?"
)

# 项目进度/计划类语义词：出现在文本中即触发人工复核或强制泛化
PROGRESS_TERMS = (
    "上线计划",
    "上线时间",
    "里程碑",
    "项目进度",
    "交付计划",
    "投产日期",
    "割接窗口",
    "排期",
    "发布时间",
    "发布窗口",
    "验收计划",
    "扩容计划",
    "迁移计划",
    "预算批复",
    "采购计划",
    "招标",
    "合同金额",
)

# 提示词注入模式：文档内容永远是不可信数据
INJECTION_PATTERNS = (
    r"忽略(?:上面|之前|以上|所有)(?:的)?(?:指令|规则|要求|提示)",
    r"ignore\s+(?:all\s+)?(?:previous|above)\s+instructions",
    r"system\s*prompt",
    r"你现在是|DAN|jailbreak",
    r"输出(?:所有|全部)(?:项目|资源|数据|记录)",
    r"列出所有(?:项目|系统|资源)",
    r"dump\s+all|export\s+all",
    r"reveal\s+(?:the\s+)?(?:secrets?|hidden)",
    r"disregard\s+.*rules?",
    r"把(?:之前|上面)的(?:内容|对话|上下文).*(?:输出|打印|复述)",
)

# 枚举/拼图探测意图
ENUMERATION_PATTERNS = (
    r"所有项目",
    r"全部系统",
    r"每个项目",
    r"逐(?:个|一)",
    r"全量(?:导出|列出|清单)",
    r"list\s+all|all\s+projects|every\s+project",
)


@dataclass(frozen=True)
class Detection:
    kind: str
    value: str
    severity: str = "medium"


def detect_injection(text: str) -> list[Detection]:
    found: list[Detection] = []
    lowered = text.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern.isascii():
            if re.search(pattern, lowered, re.IGNORECASE):
                found.append(Detection("prompt_injection", pattern, "high"))
        elif re.search(pattern, text):
            found.append(Detection("prompt_injection", pattern, "high"))
    return found


def detect_enumeration_intent(text: str) -> bool:
    lowered = text.lower()
    for pattern in ENUMERATION_PATTERNS:
        target = lowered if pattern.isascii() else text
        if re.search(pattern, target, re.IGNORECASE):
            return True
    return False


RE_MILESTONE_TERM = re.compile(
    r"(?:上线|投产|交付|发布|割接|验收|迁移|扩容|招标|采购|预算批复|合同金额|排期)"
    r"(?:时间|日期|计划|窗口|进度)?"
)


def detect_progress_terms(text: str) -> list[str]:
    return [term for term in PROGRESS_TERMS if term in text]


def neutralize_progress(text: str) -> tuple[str, list[str]]:
    """把「上线时间 2026-08-12」这类短语整段替换为治理语义，仅替换词会留下日期。"""
    hits: list[str] = []

    def _replace(match: re.Match[str]) -> str:
        hits.append(match.group(0))
        return "治理事项（已泛化）"

    result = RE_PHRASE_DATE.sub(_replace, text)
    if RE_MILESTONE_TERM.search(result):
        hits.append("里程碑语义")
        result = RE_MILESTONE_TERM.sub("治理事项", result)
    for term in detect_progress_terms(result):
        if term not in hits:
            hits.append(term)
        result = result.replace(term, "治理事项")
    return result, hits


def detect_sensitive_values(value: str) -> list[Detection]:
    """对外输出 DLP 使用：识别不该出现在响应中的精确值。"""
    out: list[Detection] = []
    out += [Detection("ipv4", m) for m in RE_IPV4.findall(value)]
    out += [Detection("ipv6", m, "low") for m in RE_IPV6.findall(value)]
    out += [Detection("mac", m, "low") for m in RE_MAC.findall(value)]
    out += [Detection("phone", m, "high") for m in RE_CN_MOBILE.findall(value)]
    out += [Detection("email", m, "high") for m in RE_EMAIL.findall(value)]
    out += [Detection("id_card", m, "high") for m in RE_ID_CARD.findall(value)]
    out += [Detection("ak", m, "high") for m in RE_ACCESS_KEY.findall(value)]
    out += [Detection("secret", m, "high") for m in RE_SECRET_KEY.findall(value)]
    out += [Detection("money", m, "medium") for m in RE_MONEY.findall(value)]
    out += [Detection("percent", m, "low") for m in RE_PERCENT.findall(value)]
    out += [Detection("date", "-".join(m), "medium") for m in RE_DATE.findall(value)]
    if any(term in value for term in PROGRESS_TERMS):
        out.append(Detection("progress_term", "进度/计划类敏感语义", "high"))
    return out


def strip_secrets(value: str) -> str:
    """写入知识库前的强清理：凭据类信息一律移除。"""
    value = RE_SECRET_KEY.sub("[已移除凭据]", value)
    value = RE_ACCESS_KEY.sub("[已移除AK]", value)
    return value
