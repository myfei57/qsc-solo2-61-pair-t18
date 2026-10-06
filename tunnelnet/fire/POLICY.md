# 烟感确认窗口（fire confirmation window）

## 要解决的问题

旧逻辑"上报一次即火警"，做饭蒸汽、扬尘都能触发联动（关防火阀、停排风、
启动抑制），一晚上误报多次。现在一次上报只记为**疑似**，同一探测器在确认
窗口内连续上报才升为**火警**。

## 状态机（每个探测器一份活动案件 `fire_case`）

```
            首次上报                 窗口内第 N 次上报
  none ───────────────▶ suspected ───────────────────────▶ alarm
   ▲                       │  │                               │
   │                       │  └── restore（恢复正常）─────────┘(仅疑似可恢复)
   │                       └────── 窗口到期 sweep ────────────┘(仅疑似自动撤销)
   └──────────────────────────── reset（人工复位，火警/疑似均可）
```

- `suspected`：仅落盘 + 审计，**不动任何物理设备**。
- `alarm`：判定先落盘，随后按序联动。
- 已确认的火警**不会**因到期或 restore 静默消失，只能 `reset`（防止真火被
  自动撤掉）。

## 两个必须定死的策略选择

### 1. 疑似到期：自动撤销（不是转人工）

定的是**自动撤销**。

- 真火：火不会自行恢复，窗口后仍会持续上报，第一次上报开新疑似、窗口内第
  二次即确认，最坏只多等一个窗口的发现时间（默认 30s 量级），安全损失有界。
- 误报（蒸汽/扬尘）：通常只触发一两下，窗口内凑不够连续次数，到期自动撤，
  夜间无需值守干预——这正是本次诉求的核心。
- 转人工的代价是每个误报都要人处理，夜间无人时疑似会挂到天亮，等于把噪声
  留给值班人员；故不采用。

### 2. 窗口按时间算（滚动时间窗）+ 窗口内次数门限

定的是**按时间**，不是按纯次数。默认 `window_seconds=30`、`required_reports=2`。

- 纯次数窗下，相隔几小时的两次蒸汽也会凑成一次火警，挡不住"慢"误报。
- 时间窗表达的是"持续在冒烟"：两次上报必须落在同一窗口内才确认。
- 次数门限仍然保留（默认 2，可调到 3 等），用于压制单次毛刺。
- 边界：第二次上报时刻 `<= 首次 + window` 即算窗口内；超出则开新窗口、计数
  从 1 重新开始。

参数在 `console/runtime.py` 的 `DEFAULT_WINDOW_SECONDS` /
`DEFAULT_REQUIRED_REPORTS`，策略对象是 `tunnelnet.fire.Policy`，构造时会
拒绝非正窗口和小于 2 的次数。

## 判定、落盘、审计共用同一份结论

纯函数 `adjudication.adjudicate(...)` 产出一个不可变 `Decision`（含
`id`、`before/after`、`trigger`、`at`、窗口参数、次数）。**同一个 Decision**
被：

1. 追加写入 `fire_decision`（只增不改）；
2. 写进审计 `Record.ref = decision.id`；
3. 升级时作为联动记录 `LinkageRecord.decision_id` 的引用。

因此审计条目、持久化判定、联动记录三者引用同一 id，不可能各说各话。

## 确认 → 联动 → 撤销的时序

升级（suspected → alarm）：

1. 先把 `Decision` 落盘（**确认先于联动**）；
2. 再按序执行联动：关源区防火阀 → 停排风 → 源区抑制 → 邻区抑制
   （`activation_order`，源区优先）；
3. 全部成功后才写一条 `fire_linkage` 生效记录，**该记录不可改写**
   （同 id 再写抛 `ValueError`）。

联动部分失败：

- 已生效的步骤按**逆序补偿**（释放邻区抑制 → 释放源区抑制 → 启排风 →
  开防火阀）；
- 不写"生效"联动记录；案件回退为 `suspected`（可重试）；
- 额外追加一条 `linkage_failed` 判定和 `fire_linkage_rolled_back` 审计。

撤销（restore / 到期 / reset）：

1. **先逆序回滚已生效联动**（查该案件的 `escalate` 记录补偿），写
   `unlink:*` 撤销记录；
2. 然后删除活动案件 `fire_case`、保留 `fire_decision` 历史；
3. restore/到期只能撤疑似；reset 可撤火警。

## 幂等

- 每个上报带 `event_key`（未带则用 `detector_id:at` 兜底）。
- 已处理的 key 记两处：内存 `MarkSet`（快速去重）+ 落盘 `mark`（重启后仍
  去重）；活动案件里也保留本窗口用过的 key。
- 重复上报返回状态不变的 no-op `Decision`，不重复联动、不重复计数、不重复
  审计。
- 疑似被撤销后同 key 的旧报文重放仍然是 no-op，不会让旧事件复活。

## 存储三类记录（`tunnelnet/fire/persistence.py`）

| kind            | 语义                                   | 可变性       |
|-----------------|----------------------------------------|--------------|
| `fire_case`     | 每探测器一份活动案件                   | 随状态改写/撤销时删除 |
| `fire_decision` | 每次判定（含 no-op 之外的全部状态变化）| 只增，不改不删 |
| `fire_linkage`  | 已生效联动（escalate）及其撤销回滚     | 只增，id 冲突即拒绝 |

## HTTP 接口

- `POST /api/fire/detect` `{detector_id, at, event_key, restored?}`：过确认窗。
- `POST /api/fire/restore`：探测器恢复，撤疑似。
- `POST /api/fire/sweep` `{at?}`：自动撤销到期疑似。
- `POST /api/fire/reset` `{detector_id, at?}`：人工复位火警/疑似。
- `GET /api/fire/alarms`：活动案件（含 suspected / cases）。
- `GET /api/fire/decisions`、`GET /api/fire/linkages`：只增历史。
- 旧的 `/api/fire/smoke`、`/api/fire/zone`、`/api/fire/alarm` 保留兼容。
