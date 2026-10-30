"""输出 DLP：模型响应在返回用户前必须过一遍。

与输入侧脱敏互为纵深：输入侧保证「不该进的进不来」，输出侧保证「不该出的出不去」。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from rg_contracts.security.detectors import (
    RE_ACCESS_KEY,
    RE_CN_MOBILE,
    RE_DATE,
    RE_EMAIL,
    RE_ID_CARD,
    RE_IPV4,
    RE_MONEY,
    RE_PERCENT,
    RE_SECRET_KEY,
    detect_progress_terms,
    detect_sensitive_values,
)
from rg_contracts.security.policy import Subject


@dataclass
class DlpFinding:
    kind: str
    severity: str
    sample: str


@dataclass
class DlpResult:
    clean: bool
    findings: list[DlpFinding] = field(default_factory=list)
    redacted_text: str = ""

    @property
    def severity(self) -> str:
        if not self.findings:
            return "none"
        if any(f.severity == "high" for f in self.findings):
            return "high"
        if any(f.severity == "medium" for f in self.findings):
            return "medium"
        return "low"


class OutputDlp:
    """默认严格模式：高精度敏感值一律阻断，中低精度做脱敏后放行。"""

    BLOCK_SEVERITY = {"high"}
    REDACT_RULES = (
        (RE_ID_CARD, "[已脱敏]"),
        (RE_CN_MOBILE, "[已脱敏]"),
        (RE_EMAIL, "[已脱敏]"),
        (RE_ACCESS_KEY, "[已移除AK]"),
        (RE_SECRET_KEY, "[已移除凭据]"),
        (RE_IPV4, "[已脱敏IP]"),
        (RE_DATE, "[已泛化日期]"),
        (RE_MONEY, "[已区间化金额]"),
        (RE_PERCENT, "[已区间化比例]"),
    )

    def inspect(
        self,
        text: str,
        subject: Subject | None = None,
        allowed_terms: Iterable[str] | None = None,
    ) -> DlpResult:
        allowed = set(allowed_terms or ())
        findings = [
            DlpFinding(kind=d.kind, severity=d.severity, sample=d.value)
            for d in detect_sensitive_values(text)
        ]
        # 进度类语义对低权限角色一律阻断
        if subject and subject.role in ("viewer", "auditor"):
            for term in detect_progress_terms(text):
                if term not in allowed:
                    findings.append(DlpFinding("progress_term", "high", term))

        blocking = [f for f in findings if f.severity in self.BLOCK_SEVERITY]
        redacted = text
        for regex, replacement in self.REDACT_RULES:
            redacted = regex.sub(replacement, redacted)
        for term in detect_progress_terms(redacted):
            if term not in allowed:
                redacted = redacted.replace(term, "治理事项")
        return DlpResult(clean=not blocking, findings=findings, redacted_text=redacted)

    def enforce(self, text: str, subject: Subject | None = None) -> str:
        from rg_contracts.errors import LeakageBlockedError

        result = self.inspect(text, subject)
        if not result.clean:
            # 只回 kind/severity，**绝不回 sample**：拦截响应会原样交给调用方，
            # 带上样本等于把刚拦下的敏感值又送回去（攻击者可反复试探纠错）。
            raise LeakageBlockedError(
                "输出包含敏感信息，已被安全策略拦截",
                findings=[{"kind": f.kind, "severity": f.severity} for f in result.findings],
            )
        return result.redacted_text


def default_dlp() -> OutputDlp:
    return OutputDlp()
