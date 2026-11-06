# 设计正本 · action-gate

## 0. 出处声明（clean-room）

- 本仓代码在独立目录从零编写，不来自任何同型实现的拷贝，
  首个提交即含设计与实现；本地 git log 与 GitHub push 时间是确权锚点。
- 编写过程中**未打开、未复制**任何同型第三方实现的 `src/`。公开材料只用于确认「问题真实存在」，
  不用于取符号或取文本。
- 命名表（本仓自有）：`verdict`（裁决四态）· `rule / predicate / subject`（规则/谓词/主体）·
  `grant`（动作凭证）· `ledger`（账本）· `action class`（动作类）。

## 1. 判据语义

一次动作 = `{tool, args}`。裁决函数：

```
decide(action, state) -> { verdict, rule_id, predicate, subject, reason }
verdict in { allow, deny, review, ask }
```

- `allow` —— 无规则命中，或命中规则被有效 `grant` 覆盖。放行但入账。
- `deny` —— 命中 deny 类规则且无凭证。**回执必须可解释**：规则 id + 哪个谓词 + 匹到的主体原文。
- `review` —— 命中但判据不完备（主体解析不出来、依赖信息缺失）⇒ **不许猜，交人**。
  四态是设计核心：只出两态的规则引擎，会把「不知道」悄悄变成「允许」或「拒绝」。
- `ask` —— 规则声明需要一次性授权，走宿主交互。

求值顺序：规则按文件顺序求值，**首个 deny 生效**（deny 优先于 allow）。失败方向应当是
「拦住且可解释」，而不是「放过且无声」。`review` 不阻断后续求值；全部求完仍无 deny ⇒ 取 `review`。

## 2. 主体（subject）提取

规则不匹配「命令字符串像不像」，匹配**从命令里解析出来的动作对象**。
纯文本距离匹不上真动作：要么漏，要么误伤——这是本组件唯一必须做对的一层。

```
subject kinds: path | url | host | env | cmd
  path = 引号或 $/盘符起始的绝对路径
  url  = https?:// 直到空白或引号
  host = url 的 hostname
  env  = 【显式】环境变量引用：$env:X / ${env:X} / %X% / printenv X，长度>=3
  cmd  = 删除/移动/覆盖类动词的宾语（解析宾语，不做文本距离）
```

每个 subject 带 `source_field`（从哪个参数抽出）与 `arg_name`（写/删类参数还是纯字符串）。

## 3. 规则 DSL

```json
// 真实文件 rules/default.json 里的一条，逐字照抄。
// 为什么是 JSON 而不是 YAML：形如 credential|token|secret 的正则裸写在 YAML 里，
// `|` 会被当块标量起始符而静默变形——解析器一错，代价就是误拦或漏拦。
// JSON 解析失败至少会抛出来；loadRules 还会拒绝未知字段与 verdict:"allow"。
{
  "id": "credential-exfil-outbound",
  "action_class": "net-send",
  "verdict": "deny",
  "reason": "把凭据形态的对象发往外部主机。认证头携带不算出境；URL 路径里出现 token 这个词也不算（实测误拦插件页）。",
  "when": {
    "subject_kind": [
      "url"
    ]
  },
  "also": {
    "subject_credentialish": true,
    "args_re": "\\b(Invoke-RestMethod|Invoke-WebRequest|curl|wget|fetch|POST|PUT|Upload)\\b"
  },
  "unless": {
    "subject_re": "^(localhost|127\\.0\\.0\\.1|\\[::1\\]|api\\.github\\.com|registry\\.npmjs\\.org|.*\\.dsh-plugin.*|192\\.168\\.|awesome-dsh-plugin\\.com|dshmarket\\.com)"
  }
}
```

要点：

- `when` 钉**主体域**（这条只允许 url 类主体参与判定），`also` 里两个谓词**同真**才 deny：
  既要有凭据形态的对象，又要有外发动词。单凭凭据字样出现在参数里就拦，
  会把「读取凭据文件」误判成外传（实测就是靠这条区分开的）。
- **认证头携带凭据 = 使用授权；凭据出现在载荷 / URL / 异域 = 外传**。两者必须分开判。
- `unless` 是白名单，不是「关掉规则」：localhost / 回环 / 官方注册域 / 内网段命中即不拦。
  ⚠ 内网段这条有已知代价——发往局域网的外传不设防，见 README「已知边界」。

## 4. 动作凭证（grant）

```
grant = base64url(payload) + '.' + hex(hmac_sha256(payload, KEY))
payload = { cls, scope_prefix, uses, exp, issued_by, note }
```

- KEY 只存在于宿主进程环境或工作区外文件；**插件不向工具暴露任何签发接口** ⇒ 模型不可自签。
- 校验三件事：签名、未过期、`scope_prefix` 是被拦主体的前缀。任一不满足 ⇒ 凭证无效，维持 deny。
- 每次消耗 `uses -= 1` 并**立即入账**（含 used_at 与命中的 rule_id）。
  凭证不是「关掉规则」，是「这一次、这个范围、放行一次」，并留下谁批的记录。

## 5. 账本

只追加 JSONL，一行一裁决：
`{ts, verdict, rule_id, predicate, subject, tool, arg_keys, grant_id?, outcome?}`。
不记参数全文（避免把凭据抄进账本），只记命中主体与字段名。轮转保留归档，绝不原地改写。

## 6. 钩子映射（DSH）

| 钩子 | 动作 |
|---|---|
| `tools/pre-execute` | decide ⇒ deny/review 时返回阻断回执（含解释） |
| `agent/pre-step` | 只做完整性检查，不改写消息（观察面不授权） |
| `tools/post-execute` | 失败回执 ⇒ 记 `outcome=failed`，喂误拦统计 |
| `tools/result` | 纯入账 |
| 只读工具 | `gate_status` / `gate_explain` / `gate_audit` |

## 7. 明确不做

- 不做公式化系统论：没有五变量模型、没有推导、没有哲学层。
- 不解释模型内部。判据只看动作与主体。
- 不做分层授权、不卖完整版。MIT。
- 不承诺预测。它只做当下的裁决；「说得出为什么拦」是它的全部主张。