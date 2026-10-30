"""预置演示数据。

目标：开箱即可演示完整链路（采集 → diff → 安全RAG归因 → 治理闭环 → 审计告警），
同时内置安全金丝雀，用于验证敏感信息不会进入向量与模型上下文。

生产部署请设置 DEMO_SEED=false。
"""

from __future__ import annotations

import random
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from rg_contracts.config import Settings, get_settings
from rg_contracts.db.models import (
    Attribution,
    CloudAccount,
    KnowledgeChunk,
    KnowledgeDocument,
    ModelGatewayConfig,
    Organization,
    Project,
    ProjectMember,
    Resource,
    ResourceDiff,
    Snapshot,
    SnapshotState,
    User,
    new_id,
    ts,
)
from rg_contracts.enums import (
    Classification,
    DiffKind,
    EvidenceLevel,
    GovernanceStatus,
    ModelProvider,
    Platform,
    ResourceKind,
    Role,
    SnapshotStatus,
)
from rg_contracts.knowledge.chunking import chunk_markdown
from rg_contracts.security.canary import CanarySet
from rg_contracts.security.sanitize import Sanitizer

# ------------------------------------------------------------------ 演示组织

ORG_ID = "org_life_ops"

PROJECTS = [
    {
        "id": "prj_core_policy",
        "code": "CORE-POL",
        "name": "核心承保系统",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "criticality": 3,
        "pm": "李project_pm_01",
        "budget": 420000.0,
        # 金丝雀：绝不应出现在向量/模型上下文
        "canary": {
            "code": "ZB-POLICY-7742",
            "owner": "沈肆",
            "milestone": "2026-11-19",
            "amount": "386500",
            "note": "双十一大促前置扩容，勿对外",
        },
    },
    {
        "id": "prj_claim",
        "code": "CLM-SVC",
        "name": "理赔服务平台",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "criticality": 2,
        "pm": "王project_pm_02",
        "budget": 260000.0,
        "canary": {
            "code": "ZB-CLAIM-3185",
            "owner": "崔柒",
            "milestone": "2027-01-08",
            "amount": "152300",
            "note": "监管检查前完成迁移",
        },
    },
    {
        "id": "prj_agent",
        "code": "AGT-MOB",
        "name": "代理人移动端",
        "classification": Classification.L2_INTERNAL.value,
        "criticality": 2,
        "pm": "赵project_pm_03",
        "budget": 150000.0,
        "canary": {
            "code": "ZB-AGENT-9920",
            "owner": "孟玖",
            "milestone": "2026-12-03",
            "amount": "74800",
            "note": "渠道压测窗口敏感",
        },
    },
    {
        "id": "prj_data",
        "code": "DAT-LAKE",
        "name": "数据中台",
        "classification": Classification.L4_SECRET.value,
        "criticality": 3,
        "pm": "陈project_pm_04",
        "budget": 680000.0,
        "canary": {
            "code": "ZB-DATA-5517",
            "owner": "陆拾",
            "milestone": "2027-03-21",
            "amount": "912400",
            "note": "涉及客户敏感数据迁移",
        },
    },
]

USERS = [
    {
        "id": "usr_admin",
        "subject": "admin@corp.local",
        "name": "平台管理员",
        "role": Role.ADMIN.value,
        "ceiling": Classification.L4_SECRET.value,
        "projects": [p["id"] for p in PROJECTS],
        "password": "Admin@2026",
    },
    {
        "id": "usr_gov",
        "subject": "governance@corp.local",
        "name": "资源治理岗",
        "role": Role.GOVERNANCE.value,
        "ceiling": Classification.L3_CONFIDENTIAL.value,
        "projects": [p["id"] for p in PROJECTS],
        "password": "Gov@2026",
    },
    {
        "id": "usr_pm",
        "subject": "pm@corp.local",
        "name": "项目经理（仅核心承保）",
        "role": Role.PM.value,
        "ceiling": Classification.L3_CONFIDENTIAL.value,
        "projects": ["prj_core_policy"],
        "password": "Pm@2026",
    },
    {
        "id": "usr_auditor",
        "subject": "auditor@corp.local",
        "name": "审计员",
        "role": Role.AUDITOR.value,
        "ceiling": Classification.L3_CONFIDENTIAL.value,
        "projects": ["prj_claim"],
        "password": "Audit@2026",
    },
    {
        "id": "usr_viewer",
        "subject": "viewer@corp.local",
        "name": "只读用户（无项目授权）",
        "role": Role.VIEWER.value,
        "ceiling": Classification.L2_INTERNAL.value,
        "projects": [],
        "password": "View@2026",
    },
]

ACCOUNTS = [
    {"id": "acc_bk", "platform": Platform.BK.value, "name": "蓝鲸-生产", "region": "cn-north-1"},
    {"id": "acc_qy", "platform": Platform.QINGCLOUD.value, "name": "青云-生产", "region": "cn-east-2"},
    {"id": "acc_hw", "platform": Platform.HUAWEI.value, "name": "华为云-生产", "region": "cn-south-1"},
    {"id": "acc_tc", "platform": Platform.TENCENT.value, "name": "腾讯云-生产", "region": "cn-east-3"},
]

# ------------------------------------------------------- 知识库（净化后内容）

KNOWLEDGE_DOCS = [
    {
        "title": "资源新增类差异治理规则",
        "doc_type": "rule",
        "project_id": None,
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "新增资源差异处理规则：1) 核对是否有对应的资源申请单与预算归属；"
            "2) 无申请单的新增判定为账外资源，需要补录或下线；"
            "3) 测试环境新增资源超过保留期限应自动提醒释放；"
            "4) 涉及项目进度与排期的信息一律不在本系统记录。"
        ),
    },
    {
        "title": "资源释放类差异治理规则",
        "doc_type": "rule",
        "project_id": None,
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "资源消失差异处理规则：1) 先确认是否为计划内下线，核对调拨单与下线审批；"
            "2) 非计划消失需要排查是否采集口径变化或账号权限变更导致的漏采；"
            "3) 已下线的资源应从台账归档并释放预算占用。"
        ),
    },
    {
        "title": "规格变更与成本归因规则",
        "doc_type": "rule",
        "project_id": None,
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "规格变更归因规则：1) 升配通常与业务容量评估、活动保障相关，需核对容量评估记录；"
            "2) 降配常见于闲置治理与成本优化动作；3) 规格与费用同时变化时应核对计费口径是否一致；"
            "4) 成本区间仅用于归因判断，不作为对外披露口径。"
        ),
    },
    {
        "title": "闲置资源识别与处置 SOP",
        "doc_type": "sop",
        "project_id": None,
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "闲置资源处置 SOP：1) 连续两个采集周期状态为停止且无流量的资源进入候选清单；"
            "2) 通知责任人确认，未在规定期限内确认的默认进入下线流程；"
            "3) 下线前保留快照证据，下线后更新台账并归档。"
        ),
    },
    {
        "title": "账实不符排查 SOP",
        "doc_type": "sop",
        "project_id": None,
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "账实不符排查 SOP：1) 以采集到的在用资源口径核定续采数量；"
            "2) 对计费量大于实际在用量的异常项向厂商提出质疑；"
            "3) 每季度输出账实不符清单并跟踪处理结果；"
            "4) 排查结论只记录资源编号与处置动作，不记录人员与排期信息。"
        ),
    },
    {
        "title": "多云采集口径与差异说明",
        "doc_type": "rule",
        "project_id": None,
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "多云采集口径说明：1) 各平台资源 ID 命名空间不同，统一以平台+原生ID作为唯一键；"
            "2) 规格字段需归一化为 CPU 与内存区间；3) 标签差异用于成本中心归属判断；"
            "4) 采集失败时标记为部分成功，不覆盖上一次成功快照。"
        ),
    },
    # ---- 项目内知识：评测要能测「项目维度」，语料就必须真有项目分片。
    # 此前全部是全局文档，于是「越权题」实际没有可泄漏的内容（拒绝是必然的，
    # 测不出过滤是否写对），项目内召回也无从测量。分片数也随之后续大于 top_k，
    # recall 才不饱和。
    # 内容约定：只写标题类治理规则，不放项目金丝雀值（code/owner/amount 等），
    # 否则「知识库泄漏」和「金丝雀泄漏」两类判定会互相污染。
    {
        "title": "核心承保系统双活切换手册",
        "doc_type": "runbook",
        "project_id": "prj_core_policy",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 适用与前置条件\n\n"
            "双活切换执行条件：1) 只在变更委员会确认的计划窗口内执行；"
            "2) 切换前核对主备复制延迟，延迟超过三十秒禁止切换；"
            "3) 切换顺序为冻结写入、确认备库追平、再切换连接串。\n\n"
            "## 执行与校验\n\n"
            "4) 切换后十分钟内校验承保交易成功率与单据落库数量；"
            "5) 校验失败按回滚脚本切回主集群，回滚不晚于切换开始后三十分钟；"
            "6) 切换期间冻结批量代扣作业，避免重复扣款。\n\n"
            "## 记录与留档\n\n"
            "7) 每次切换记录执行人、时间戳与校验结论；"
            "8) 切换记录不写入客户信息与保单明细；"
            "9) 双活演练每季度一次，结论纳入可用性报告。"
        ),
    },
    {
        "title": "核心承保系统容量评估与升配流程",
        "doc_type": "sop",
        "project_id": "prj_core_policy",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 评估口径\n\n"
            "容量评估与升配流程：1) 升配申请须附容量评估记录，窗口覆盖最近四个采集周期；"
            "2) CPU 峰值水位连续两周超过七成才进入升配评估；"
            "3) 内存水位按 P95 取值，不用单次尖峰作为依据。\n\n"
            "## 审批与复核\n\n"
            "4) 升配工单需项目经理与资源治理岗双签；"
            "5) 升配后两周内复核水位，未下降的须写明原因；"
            "6) 降配与升配同一套评估口径，额外确认业务排期不受影响。\n\n"
            "## 记录与留档\n\n"
            "7) 规格变更需同步核对计费口径是否一致；"
            "8) 评估记录在知识库留档，保留期与项目审计周期一致。"
        ),
    },
    {
        "title": "核心承保系统数据库账号权限审批规范",
        "doc_type": "rule",
        "project_id": "prj_core_policy",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 授予原则\n\n"
            "数据库账号权限规范：1) 账号按角色授予，禁止按人授予单一账号；"
            "2) 生产账号只读与可写分离，写权限需单独审批。\n\n"
            "## 有效期与回收\n\n"
            "3) 权限申请须写明用途与有效期，最长不超过九十天；"
            "4) 到期未续期的权限自动回收；"
            "5) 每季度复核一次账号清单，清理长期未使用的账号。\n\n"
            "## 与其他流程的关系\n\n"
            "6) 账号变更与双活切换解耦，不因切换放宽权限；"
            "7) 权限审批记录只保留账号与角色，不保留口令。"
        ),
    },
    {
        "title": "核心承保系统变更窗口管理规则",
        "doc_type": "rule",
        "project_id": "prj_core_policy",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 窗口安排\n\n"
            "变更窗口规则：1) 常规变更窗口为周二与周四夜间，避开承保出单高峰；"
            "2) 紧急变更需项目经理与值班负责人共同批准；"
            "3) 同一窗口内的变更数量不超过三项。\n\n"
            "## 冲突与回滚\n\n"
            "4) 涉及数据库的变更不得与双活切换安排在同一窗口；"
            "5) 窗口内变更失败按回滚脚本处理，不留半完成状态。\n\n"
            "## 记录要求\n\n"
            "6) 变更记录保留变更单号、执行人与回滚结论。"
        ),
    },
    {
        "title": "理赔服务平台灾备演练计划",
        "doc_type": "sop",
        "project_id": "prj_claim",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 演练范围与周期\n\n"
            "灾备演练计划：1) 每半年一次，覆盖报案、立案与结案三个环节；"
            "2) 演练前冻结生产变更，窗口与监管报送窗口错开。\n\n"
            "## 执行与判定\n\n"
            "3) 以只读方式验证备中心数据完整性，不写入生产数据；"
            "4) 演练结论需给出恢复时间与数据偏差两项结果；"
            "5) 数据偏差超过阈值判定演练不通过，须重做。\n\n"
            "## 取证与备案\n\n"
            "6) 取证材料只保存系统日志与检查项结果，不保存理赔影像；"
            "7) 演练结论报审计岗备案，纳入年度合规检查。"
        ),
    },
    {
        "title": "理赔服务平台监管报送核对清单",
        "doc_type": "rule",
        "project_id": "prj_claim",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 口径来源\n\n"
            "监管报送核对清单：1) 报送前核对报送口径与实际在用资源是否一致；"
            "2) 清单以采集口径为准，不以厂商计费单为准；"
            "3) 附列的资源编号需与台账一一对应。\n\n"
            "## 变更与失败处理\n\n"
            "4) 口径变动须在报送前完成审批并留存变更记录；"
            "5) 报送失败标记为部分成功，不覆盖上一次成功结果。\n\n"
            "## 记录范围\n\n"
            "6) 核对结论只保留资源编号与结果，不记录理赔个案信息。"
        ),
    },
    {
        "title": "理赔服务平台影像数据留存规范",
        "doc_type": "rule",
        "project_id": "prj_claim",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 存储与留存\n\n"
            "影像数据留存规范：1) 理赔影像按案件归属存储，跨案件不得混存；"
            "2) 留存期与监管要求一致，到期统一清理。\n\n"
            "## 访问与导出\n\n"
            "3) 影像访问需按岗位授权，禁止全量开放；"
            "4) 影像不得进入向量库与模型上下文；"
            "5) 下载与批量导出需单独审批并记录。\n\n"
            "## 清理记录\n\n"
            "6) 清理记录保留案件编号与批次，不保留影像内容。"
        ),
    },
    {
        "title": "理赔服务平台结案作业调度说明",
        "doc_type": "sop",
        "project_id": "prj_claim",
        "classification": Classification.L3_CONFIDENTIAL.value,
        "content": (
            "## 调度顺序与依赖\n\n"
            "结案作业调度说明：1) 结案批处理在日终窗口执行，优先于报表汇总；"
            "2) 作业依赖显式声明，跨层依赖不得隐式继承。\n\n"
            "## 失败与重试\n\n"
            "3) 失败重试不超过三次，间隔按指数退避；"
            "4) 重试仍失败的作业转人工队列并告警；"
            "5) 调度冲突时以监管报送作业优先。\n\n"
            "## 日志保留\n\n"
            "6) 调度日志保留九十天，含作业名与批次号。"
        ),
    },
    {
        "title": "代理人移动端灰度发布与回滚规范",
        "doc_type": "rule",
        "project_id": "prj_agent",
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "## 灰度放量\n\n"
            "灰度发布与回滚规范：1) 灰度按渠道分批放量，首批不超过百分之五；"
            "2) 每批放量前核对崩溃率与接口错误率，任一超阈值立即暂停。\n\n"
            "## 回滚要求\n\n"
            "3) 回滚窗口不超过发布后两小时，超时需变更委员会审批；"
            "4) 灰度期间禁止同时调整渠道推送配置；"
            "5) 回滚后复测登录与保单查询两个核心链路。\n\n"
            "## 发布记录\n\n"
            "6) 发布记录保留批次、时间与结论，不记录代理人个人信息。"
        ),
    },
    {
        "title": "代理人移动端渠道压测指引",
        "doc_type": "sop",
        "project_id": "prj_agent",
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "## 窗口与环境\n\n"
            "渠道压测指引：1) 压测只在非业务高峰窗口执行，窗口提前一天报备；"
            "2) 压测目标以登录峰值与保单查询峰值为准；"
            "3) 压测前锁定渠道配置，避免压测期间口径漂移。\n\n"
            "## 流量与结论\n\n"
            "4) 压测流量走只读副本，不得打到生产主库；"
            "5) 压测结论需给出瓶颈资源与建议规格。\n\n"
            "## 收尾\n\n"
            "6) 压测后清理压测账号与临时配置。"
        ),
    },
    {
        "title": "代理人移动端版本兼容与下线规则",
        "doc_type": "rule",
        "project_id": "prj_agent",
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "## 兼容范围\n\n"
            "版本兼容与下线规则：1) 至少兼容最近三个大版本，更早版本逐步收敛；"
            "2) 强制升级须提前两周公告，并保留回退通道。\n\n"
            "## 下线条件\n\n"
            "3) 下线前确认旧版本活跃设备占比低于百分之一；"
            "4) 下线与灰度发布不得安排在同一周。\n\n"
            "## 记录\n\n"
            "5) 版本下线记录保留版本号与公告时间。"
        ),
    },
    {
        "title": "代理人移动端推送配置变更流程",
        "doc_type": "sop",
        "project_id": "prj_agent",
        "classification": Classification.L2_INTERNAL.value,
        "content": (
            "## 变更流程\n\n"
            "推送配置变更流程：1) 推送配置按渠道分组管理，变更需双人复核；"
            "2) 变更前在灰度渠道验证送达率。\n\n"
            "## 失败处理\n\n"
            "3) 送达率低于阈值时回滚配置；"
            "4) 变更窗口避开渠道压测窗口。\n\n"
            "## 记录\n\n"
            "5) 变更记录保留渠道、配置版本与结论，不保留推送内容正文。"
        ),
    },
    {
        "title": "数据中台客户数据脱敏规范",
        "doc_type": "rule",
        "project_id": "prj_data",
        "classification": Classification.L4_SECRET.value,
        "content": (
            "## 入库与规则\n\n"
            "客户数据脱敏规范：1) 客户标识、联系方式与证件号在入库前必须完成脱敏；"
            "2) 脱敏规则由数据安全岗维护，变更需双人复核。\n\n"
            "## 使用与例外\n\n"
            "3) 分析场景只允许使用脱敏后的字段组合；"
            "4) 需要原文的场景必须走单独审批并留存使用记录；"
            "5) 脱敏失败的数据不得进入向量库与模型上下文。\n\n"
            "## 抽检与日志\n\n"
            "6) 规则变更后重跑存量数据抽检，比例不低于千分之一；"
            "7) 脱敏日志只记录规则版本与处理条数，不记录字段值。"
        ),
    },
    {
        "title": "数据中台批处理调度与重试规范",
        "doc_type": "rule",
        "project_id": "prj_data",
        "classification": Classification.L4_SECRET.value,
        "content": (
            "## 调度与依赖\n\n"
            "批处理调度与重试规范：1) 作业按依赖分层调度，跨层依赖必须显式声明；"
            "2) 单作业重试不超过三次，间隔按指数退避；"
            "3) 重试仍失败转人工队列并告警。\n\n"
            "## 窗口与补数\n\n"
            "4) 调度窗口与监管报送窗口错开，避免资源争抢；"
            "5) 补数作业需标注补数范围与影响分区。\n\n"
            "## 变更与日志\n\n"
            "6) 作业变更先在测试环境验证再上线；"
            "7) 调度日志保留九十天，含作业名、批次与状态。"
        ),
    },
    {
        "title": "数据中台对象存储生命周期规则",
        "doc_type": "rule",
        "project_id": "prj_data",
        "classification": Classification.L4_SECRET.value,
        "content": (
            "## 保留期\n\n"
            "对象存储生命周期规则：1) 原始数据桶保留九十天，超期自动转归档存储；"
            "2) 归档桶保留三年，删除需走审批；"
            "3) 临时桶按天清理，保留期不超过七天。\n\n"
            "## 策略变更\n\n"
            "4) 桶策略变更需双人复核并记录变更单号；"
            "5) 跨区域复制仅在灾备场景开启；"
            "6) 生命周期规则变更后抽检一次转储结果。\n\n"
            "## 访问控制\n\n"
            "7) 存储桶禁止公网读写，策略变更后复测访问控制。"
        ),
    },
    {
        "title": "数据中台训练资源申请与配额管理",
        "doc_type": "sop",
        "project_id": "prj_data",
        "classification": Classification.L4_SECRET.value,
        "content": (
            "## 配额申请\n\n"
            "训练资源与配额管理：1) GPU 训练资源按项目配额申请，单次不超过配额上限；"
            "2) 配额调整需数据平台负责人与资源治理岗共同确认。\n\n"
            "## 运行与闲置\n\n"
            "3) 训练任务需声明预计时长，超时任务进入复核队列；"
            "4) 空闲超过一小时的训练实例进入闲置候选清单；"
            "5) 训练数据只允许使用脱敏后的数据集。\n\n"
            "## 释放与归因\n\n"
            "6) 任务结束后释放实例并核对计费口径；"
            "7) 配额使用按月汇总，纳入成本归因报告。"
        ),
    },
]


def seed_all(session: Session, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    from rg_contracts.auth.sessions import hash_password

    if session.execute(select(Project).limit(1)).scalar_one_or_none() is not None:
        return {"skipped": True, "reason": "已有数据"}

    session.add(Organization(id=ORG_ID, name="寿险应用系统开发部", code="LIFE-OPS", parent_id=None))

    for project in PROJECTS:
        session.add(
            Project(
                id=project["id"],
                code=project["code"],
                name=project["name"],
                org_id=ORG_ID,
                classification=project["classification"],
                business_criticality=project["criticality"],
                pm_name=project["pm"],
                monthly_budget_cny=project["budget"],
            )
        )

    # 父行先落库：project_member 同时依赖 user 与 project，
    # 单次 flush 的依赖排序在多父表场景下不稳定，这里显式化依赖
    session.flush()

    for user in USERS:
        session.add(
            User(
                id=user["id"],
                subject=user["subject"],
                display_name=user["name"],
                email=user["subject"],
                role=user["role"],
                org_id=ORG_ID,
                classification_ceiling=user["ceiling"],
                is_active=True,
                password_hash=hash_password(user["password"]),
                attributes={"demo": True},
            )
        )
    session.flush()

    for user in USERS:
        for pid in user["projects"]:
            project = next(p for p in PROJECTS if p["id"] == pid)
            session.add(
                ProjectMember(
                    id=new_id("pm"),
                    user_id=user["id"],
                    project_id=pid,
                    visible_ceiling=min(
                        user["ceiling"], project["classification"], key=_rank
                    ),
                    created_at=ts(),
                )
            )

    for account in ACCOUNTS:
        session.add(
            CloudAccount(
                id=account["id"],
                platform=account["platform"],
                name=account["name"],
                endpoint="",
                region=account["region"],
                credential_ref=f"{account['platform'].upper()}_CREDENTIALS",
                enabled=True,
                options={"project_ids": [p["id"] for p in PROJECTS], "resource_count": 45},
            )
        )

    session.flush()
    return {"skipped": False}


def _rank(level: str) -> int:
    from rg_contracts.enums import classification_rank

    return classification_rank(level)


def seed_knowledge(session: Session, settings: Settings | None = None) -> dict:
    """写入知识文档并生成净化分片（不落原文敏感字段）。"""
    settings = settings or get_settings()
    sanitizer = Sanitizer()
    created_docs = 0
    created_chunks = 0
    for doc in KNOWLEDGE_DOCS:
        exists = session.execute(
            select(KnowledgeDocument).where(KnowledgeDocument.title == doc["title"])
        ).scalar_one_or_none()
        if exists:
            continue
        document = KnowledgeDocument(
            id=new_id("kd"),
            title=doc["title"],
            doc_type=doc["doc_type"],
            project_id=doc["project_id"],
            platform=None,
            classification=doc["classification"],
            source_ref="seed://governance-rules",
            content=doc["content"],
            sanitized=True,
            metadata_json={"seed": True},
        )
        session.add(document)
        session.flush()
        created_docs += 1

        # 切块必须先净化再切、且用**与生产摄取同一个**切块器（``chunk_markdown``）。
        # 旧实现按 ASCII 分号硬切、目标 260 字，与 ``routes/knowledge.py`` 的
        # 标题感知切块（600 字、按章节成块、带 section_path）不是同一套——
        # 那样评测测的是"种子的形状"，不是"生产的形状"，指标对不上真实检索。
        sanitized = sanitizer.sanitize_text(doc["content"])
        for draft in chunk_markdown(sanitized.text):
            session.add(
                KnowledgeChunk(
                    id=new_id("kc"),
                    document_id=document.id,
                    ordinal=draft.ordinal,
                    section_path=draft.section_path,
                    project_id=doc["project_id"],
                    platform=None,
                    classification=doc["classification"],
                    embedding_text=draft.text,
                    display_text=draft.text,
                    token_count=len(draft.text),
                    embedding_model=settings.EMBEDDING_MODEL,
                    metadata_json={"sanitized": True, "removed": sanitized.removed},
                    created_at=ts(),
                )
            )
            created_chunks += 1
    session.commit()
    return {"documents": created_docs, "chunks": created_chunks}


def seed_demo_facts(session: Session, settings: Settings | None = None) -> dict:
    """生成演示用资源、两次快照与差异记录。"""
    settings = settings or get_settings()
    rng = random.Random(20261015)
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(days=30)
    target_time = now - timedelta(days=2)

    resources: list[Resource] = []
    for account in ACCOUNTS:
        for project in PROJECTS:
            for i in range(6):
                kind = [
                    ResourceKind.VM.value,
                    ResourceKind.DISK.value,
                    ResourceKind.DATABASE.value,
                    ResourceKind.LOADBALANCER.value,
                    ResourceKind.OBJECT_STORAGE.value,
                    ResourceKind.PUBLIC_IP.value,
                ][i % 6]
                native_id = f"{account['platform']}-{project['code'].lower()}-{i:03d}"
                resource = Resource(
                    id=new_id("res"),
                    platform=account["platform"],
                    account_id=account["id"],
                    project_id=project["id"],
                    native_id=native_id,
                    name=f"{kind}-{project['code']}-{i:03d}",
                    kind=kind,
                    region=account["region"],
                    spec=["2C4G", "4C8G", "8C16G", "16C32G", "S5.MEDIUM4"][i % 5],
                    status=["running", "running", "stopped", "running", "expired"][i % 5],
                    monthly_cost_cny=round(rng.uniform(80, 3800), 2),
                    classification=project["classification"],
                    owner=None,
                    first_seen_date=(base_time - timedelta(days=120)).date(),
                    last_seen_date=target_time.date(),
                    attributes={"tags": {"env": ["prod", "test", "dev"][i % 3]}},
                )
                resources.append(resource)
                session.add(resource)
    session.flush()

    base_snapshot = Snapshot(
        id=new_id("snap"),
        platform="multi",
        account_id=ACCOUNTS[0]["id"],
        taken_at=ts(base_time),
        status=SnapshotStatus.SUCCESS.value,
        source_mode=settings.COLLECTOR_MODE,
        resource_count=len(resources),
    )
    target_snapshot = Snapshot(
        id=new_id("snap"),
        platform="multi",
        account_id=ACCOUNTS[0]["id"],
        taken_at=ts(target_time),
        status=SnapshotStatus.SUCCESS.value,
        source_mode=settings.COLLECTOR_MODE,
        resource_count=len(resources),
    )
    session.add_all([base_snapshot, target_snapshot])
    session.flush()

    for resource in resources:
        session.add(
            SnapshotState(
                id=new_id("ss"),
                snapshot_id=target_snapshot.id,
                resource_id=resource.id,
                project_id=resource.project_id,
                platform=resource.platform,
                kind=resource.kind,
                fingerprint=_fingerprint(resource),
                monthly_cost_cny=resource.monthly_cost_cny,
                payload={"spec": resource.spec, "status": resource.status},
            )
        )

    diff_count = 0
    for idx, resource in enumerate(resources):
        # 每个项目、每种差异类型都要有样本，保证演示与联调覆盖完整
        kind_choice = idx % 4
        if kind_choice == 0:
            diff_kind = DiffKind.NEW.value
            summary = "新增资源，需核对申请单与预算归属"
            hint = "新增资源：需核对申请单与预算归属"
            delta = resource.monthly_cost_cny
        elif kind_choice == 1:
            diff_kind = DiffKind.REMOVED.value
            summary = "资源消失，确认计划内下线或漏采"
            hint = "资源释放：确认是否为计划内下线，避免账实不符"
            delta = -float(resource.monthly_cost_cny or 0)
        elif kind_choice == 2:
            diff_kind = DiffKind.SPEC_CHANGED.value
            summary = "规格变更，核对容量评估与计费口径"
            hint = "规格变更：核对变更单与容量评估"
            delta = round(float(resource.monthly_cost_cny or 0) * 0.35, 2)
        else:
            diff_kind = DiffKind.STATE_CHANGED.value
            summary = "状态变更，核对是否闲置或临时扩容"
            hint = "运行转停止：核对是否为闲置资源，评估下线或释放"
            delta = round(float(resource.monthly_cost_cny or 0) * -0.5, 2)
        session.add(
            ResourceDiff(
                id=new_id("diff"),
                project_id=resource.project_id,
                platform=resource.platform,
                resource_id=resource.id,
                native_id=resource.native_id,
                resource_name=resource.name,
                kind=resource.kind,
                diff_kind=diff_kind,
                base_snapshot_id=base_snapshot.id,
                target_snapshot_id=target_snapshot.id,
                detected_at=ts(target_time),
                cost_delta_cny=delta,
                classification=resource.classification,
                rule_hint=hint,
                summary=summary,
                payload={"spec": resource.spec, "status": resource.status, "region": resource.region},
                status=GovernanceStatus.OPEN.value,
            )
        )
        diff_count += 1

    session.commit()
    return {"resources": len(resources), "snapshots": 2, "diffs": diff_count}


def _fingerprint(resource: Resource) -> str:
    import hashlib

    raw = "|".join(
        [
            resource.platform,
            resource.native_id,
            resource.kind,
            resource.spec or "",
            resource.status or "",
            resource.region or "",
        ]
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def build_canaries() -> list[CanarySet]:
    sets: list[CanarySet] = []
    for project in PROJECTS:
        canary = project["canary"]
        sets.append(
            CanarySet(project_id=project["id"]).build(
                code=canary["code"],
                owner=canary["owner"],
                milestone=canary["milestone"],
                amount=canary["amount"],
                secret_note=canary["note"],
            )
        )
    return sets


def seed_model_gateway(session: Session, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    if session.execute(select(ModelGatewayConfig).limit(1)).scalar_one_or_none() is not None:
        return {"skipped": True}
    rows = [
        ModelGatewayConfig(
            id=new_id("mgw"),
            name="内网推理服务（默认）",
            provider=ModelProvider.INTERNAL.value,
            base_url=settings.INTERNAL_INFERENCE_BASE_URL or "http://vllm.inference.svc.cluster.local:8000",
            model=settings.INTERNAL_INFERENCE_MODEL or "deepseek-r1-distill-qwen-14b-int4",
            api_key_ref="INTERNAL_INFERENCE_API_KEY",
            api_key_masked=None,
            enabled=True,
            is_default=True,
            sanitize_before_send=True,
            temperature=0.1,
            max_tokens=2048,
            timeout_seconds=120,
            updated_by="seed",
        ),
        ModelGatewayConfig(
            id=new_id("mgw"),
            name="外部 OpenAI 兼容 API（需白名单）",
            provider=ModelProvider.OPENAI_COMPATIBLE.value,
            base_url="https://api.deepseek.com",
            model="deepseek-chat",
            api_key_ref="PUBLIC_API_KEY",
            api_key_masked=None,
            enabled=False,
            is_default=False,
            sanitize_before_send=True,
            temperature=0.1,
            max_tokens=2048,
            timeout_seconds=120,
            updated_by="seed",
        ),
    ]
    session.add_all(rows)
    session.commit()
    return {"created": len(rows)}


def seed_attribution_samples(session: Session) -> dict:
    """演示用归因结果：说明规则与 LLM 两种证据等级。"""
    diffs = session.execute(
        select(ResourceDiff).limit(6)
    ).scalars().all()
    created = 0
    for diff in diffs:
        exists = session.execute(
            select(Attribution).where(Attribution.diff_id == diff.id)
        ).scalar_one_or_none()
        if exists:
            continue
        session.add(
            Attribution(
                id=new_id("attr"),
                diff_id=diff.id,
                project_id=diff.project_id,
                task_id=new_id("task"),
                cause=diff.rule_hint or "待归因",
                confidence=0.35,
                explanation=(
                    f"规则初判：{diff.summary}。实体信息已令牌化，"
                    "未使用项目进度、负责人姓名与精确金额。"
                ),
                recommended_action="按治理 SOP 走人工复核与资源核实流程",
                evidence_level=EvidenceLevel.RULE.value,
                provider="rule",
                model_name="rule-engine",
                created_at=ts(),
            )
        )
        created += 1
    session.commit()
    return {"created": created}


def seed_everything(session: Session, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    result: dict = {}
    if settings.DEMO_SEED_FORCE:
        result["facts"] = seed_demo_facts(session, settings)
    result["base"] = seed_all(session, settings)
    result["knowledge"] = seed_knowledge(session, settings)
    result["gateway"] = seed_model_gateway(session, settings)
    if not session.execute(select(Resource).limit(1)).scalar_one_or_none():
        result["facts"] = seed_demo_facts(session, settings)
    result["attribution"] = seed_attribution_samples(session)
    return result


__all__ = [
    "ACCOUNTS",
    "KNOWLEDGE_DOCS",
    "PROJECTS",
    "USERS",
    "build_canaries",
    "seed_all",
    "seed_attribution_samples",
    "seed_demo_facts",
    "seed_everything",
    "seed_knowledge",
    "seed_model_gateway",
    "date",
]
