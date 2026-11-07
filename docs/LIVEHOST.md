# 活宿主实测记录（2026-11-07）

这一页存在的理由：README 的判据此前只到「源码核对过、真拦未实测」。现在实测了，
就把原文留在仓里 —— 拦不住别人读，也拦不住自己事后美化。

## 怎么挂上去的

`desktop` profile 归 Electron 独占，CLI 直接拒绝管理它（`profile "desktop" is managed
exclusively by the Electron application`）。而重启当前宿主会杀掉正在跑的会话。所以真拦
只能在**第二个进程 + 独立 profile** 上做：

```
C:\Users\<user>\.dsh\profiles\agtest\
  package.json          # bundles: dsh-base + dsh-headless；dependencies.action-gate = link:.
  cordis.yml            # []
  ag-overlay.patch.yml  # - insert: {id: action-gate, name: action-gate, config: {rules: ...}}
  node_modules\action-gate  # 目录联接（mklink /J）指向仓 ⇒ 改代码免重装
```

跑法：`dsh --profile agtest --patch <overlay> --dump-config` 先确认闸门是最后一层，
再 `dsh --profile agtest --patch <overlay> "<任务>"`（headless：答一个任务就退出）。

## 阳性对照（真拦，一次动作都没落地）

任务里先跑一条良性命令，再跑一条 deny 形状的。**关键设计：被拦的那条读的是我自己在
子进程环境里塞的假值 `AG_DUMMY_SECRET`，不是任何真密钥** —— 万一闸门失效，进日志的也只是它。

良性调用返回：
```
2026年11月7日 8:13:22
```

被拦调用的错误原文（一字未改，模型原样贴回）：
```
Error: [action-gate·env-secret-echo] 打印【显式】凭据环境变量的值（$env:X / %X%，会进事件账并随后续请求上行）。只报长度或形状不算。｜主体=env:AG_DUMMY_SECRET｜判据=subject_kind=env & 凭据形态主体 env:AG_DUMMY_SECRET ; subject_kind=env & args_re
```

尾部的 `args_re` 不是截断，就是谓词字符串本身长这样（`rules.js` 的 `why`）。

同轮账本（`ACTION_GATE_LEDGER`）3 行：

```
{"verdict":"allow", ...}
{"verdict":"deny", "rule_id":"env-secret-echo", "subject":{"kind":"env","value":"AG_DUMMY_SECRET"}}
{"verdict":"observed", "stage":"post-failure", "tool":"pwsh"}
```

两次工具调用 ⇒ 两行裁决：`tools/pre-execute` 与 `guard` 共享按 `callId` 的记忆化，
没有落双份账。

## `ask` / `review` 在无审批通道会话里的真实后果

文档里那句「缺审批支持时 ask 自动降级为拒绝」，实测形状是宿主的硬失败，不是我的文案：

```
Error: tool "pwsh" requires approval, but no approval channel is available
```

命令一次都没进入 pwsh 进程。**含义**：在无审批通道的会话里常开 `git-push-to-remote`，
效果是所有 `git push` 永久失败 —— 想让它真的「问一句」，得在有审批通道的会话里用。

## 顺带测出来的两个洞（已修）

| 现象 | 根因 | 修复后回放 |
|---|---|---|
| `env-secret-echo-implicit` 在 21k 样本 0 命中 | `isCredentialish2` 没有 `env-implicit` 分支 ⇒ 落到末尾 `return false`，规则**结构上永不可能命中** | 命中 2 |
| `recursive-delete-root-shape` 31 条命中里 4 条主体是 `/dev/null` | `isRootish` 没排除设备结点，`2>/dev/null` 极常见且 `/dev` 落在系统树里 | 命中 27，deny 157→153 |

教训写在这儿而不是只留在 commit 里：**一条规则在真实语料上恒 0 命中，第一解释是它坏了，
不是「这个场景没发生过」**。前者一行判据就能测，后者要等到出事。

## 仍未验收

- 图形界面里那个「要不要批准」的弹窗：本机演示跑在 headless，看不到 `ask` 的**正向** UX。
- 多插件同时挂 `guard` 的顺序交互：只验了「后挂的插件翻不回 allow」这一半。
