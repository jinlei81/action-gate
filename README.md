# action-gate

给跑在 DeepSeek Harness 上的 agent 挂一道**动作闸门**：工具执行前按确定性规则裁决 allow / deny / review，
宿主签发的**动作凭证**决定例外，所有裁决进**只追加账本**。

零 LLM、零领域知识、不读任何模型内部状态。规则是人写的 **JSON**（自写 YAML 解析器一旦误解 = 静默误拦，
所以宁可丑）；未知字段直接报错，`verdict:"allow"` 被 `loadRules` 拒收（防止某条规则被悄悄解除）。

## 为什么是它，不是什么

这不是一套理论，是一个组件。它只主张四件事，每件都能被一行测试证伪：

1. **执行前拦，而不是事后审。** 审计日志告诉你昨天坏了什么；闸门告诉你下一步不许做。
2. **裁决要能解释。** 拦住时必须给出「哪条规则、匹上哪个谓词、命中哪个主体」，不给「模型觉得不该做」。
3. **例外要宿主签。** 被拦的一方（模型）不能自己发通行证；凭证由宿主侧签发、带作用域与次数、用完即失效。
4. **只读面不是授权面。** 任何查询/观察/统计接口都不产生权限，永远不。

## 30 秒跑起来

```bash
node --test test/engine.test.mjs   # 引擎判据回归（34 例）
node scripts/replay.mjs            # 在【自己的】历史会话上回放，出拦截密度与逐条 deny
```

回放默认读 `~/.dsh/sessions/*/session.v4.jsonl.zstd`（`ACTION_GATE_SESSIONS` 可覆盖）。
**没有附带语料**：拦得对不对只有在你自己的历史调用上跑才算数，别人替你测出来的数字不算。

挂载（DSH profile）：把 `action-gate.patch.yml` 接进你的 profile overlay，运行在该 profile 的
agent 自动获得 `gate_status` / `gate_explain` / `gate_audit` 三个只读工具与两道写路径闸门。

钩子选型不是照着文档猜的：`guard` 必须回【字符串】（回对象会渲染成 `[object Object]`）、
`ask` 的字段名是 `reason` 不是 `question`、工具定义必须带 `output.render`（缺了整条插件
静默不激活）。三个坑都在 `src/index.js` 头部注释里留了记录。

## 目录

| 路径 | 内容 |
|---|---|
| `docs/DESIGN.md` | 判据语义、规则 DSL、凭证格式（**这份是设计正本**） |
| `docs/REPLAY.md` | 口径怎么定的、以及哪些指标已被实测证伪（别照抄） |
| `docs/LIVEHOST.md` | 活宿主真拦实测记录：挂载方式、被拦原文、以及两条恒 0 命中的规则为什么是坏了而非没遇到 |
| `src/rules.js` | 规则加载 + 谓词匹配（纯函数，无依赖） |
| `src/engine.js` | 裁决：规则 × 凭证 × 账本 |
| `src/grant.js` | 宿主侧凭证签发/校验（HMAC，模型不可自签） |
| `src/ledger.js` | 只追加 JSONL 账本 |
| `src/index.js` | DSH 插件入口：`guard` + `tools/pre-execute` + `tools/result` 三个钩子、三个只读工具 |
| `rules/default.json` | 起步规则集（10 条，本机真实踩过的坑写的，非示例；无硬编码本机路径） |
| `scripts/replay.mjs` | 历史调用回放器：多帧 zstd 切帧、按会话目录还原工作区根、阳性对照不过就 exit 3 |

## 出处与边界

本工程独立编写，未使用任何第三方同型实现的代码。设计动机来自公开可见的一类问题
（agent 越界动作、护栏不可解释、误拦无人调）；表达、命名、判据、测试均为本仓自有。
详见 `docs/DESIGN.md` 第 0 节。

## 已知边界（先说坏消息）

- **`credential-exfil-outbound` 的白名单整块是死码（2026-11-07 实测，7/7 分支全部无效）**。
  `when.subject_kind` 只放行 url 主体参与判定，而 url 主体的值是 `http://192.168.3.237/x` 这种**带 scheme 的整串**；
  `unless` 的正则用 `^(localhost|127\.0\.0\.1|…|192\.168\.|…)` 锚定域名 ⇒ 一条都匹不上。
  实测后果：带 `?api_key=值` 的出境命令发往 localhost / api.github.com / registry.npmjs.org /
  插件域名 / 192.168.\* / 公网，**一律 deny**（含文档里写「实测误拦插件页」那条 —— 它的出口当时也没生效）。
  修法一行：把 `unless.subject_kind` 设成 `["url","host"]`（`host` 主体是纯域名，已在抽取层生成）。
  ⇒ **本条只记录、未改规则**：改成哪种放行范围（整段内网 / 只 237 / 保持严格）等用户定。
- **`ask` 命中 8/21.4k**（全来自 `git-push-to-remote`；逐条上限原先硬编码 25，会把「某规则 0 命中」的三种成因混成一个 —— 已加 `ACTION_GATE_DENY_RULE` / `DENY_LIMIT`）。实测：会话里没有审批通道时，宿主把它
  变成硬失败 —— `tool pwsh requires approval, but no approval channel is available`，命令一次都没进进程。
  ⇒ 在无审批通道的会话里常开，这条会把所有 `git push` 变成失败，而不是「问一句」。
- **真拦已在活宿主实测**（2026-11-07）：独立 profile + 第二个进程装上后，`Write-Host $env:AG_DUMMY_SECRET`
  被 `env-secret-echo` 挡在执行之前，闸门理由原样回到会话里；同轮的良性调用照旧放行。
  ⚠ 宿主【重启才会】重新 require 插件：改完 `src/index.js` 不重启，跑的还是旧版。
- **规则不是策略完备集**：它是本机踩坑的沉淀，不是通用清单。换一台机器、换一类工作，
  先用自己历史回放一遍再决定是否常开。

## 许可

MIT —— 见 `LICENSE`。本仓不做分层授权，不卖"完整版"。
