// DSH 插件入口。
//
// 机制选型（2026-11-07 逐条在活宿主源码核对，非推测）：
//   · ctx.tools.guard(fn)：fn【必须返回拒绝理由字符串或 undefined】。
//     依据 pipeline.js:154/402 —— decision.kind==="allow" 时才查 checkGuards(exec)，
//     返回值直接拼成 `Error: ${denialReason}` 且 isError:true。回对象会渲染成 [object Object]。
//     它是【单调拒绝】通道：别的插件无法在后续钩子里把它翻回 allow。
//   · ctx.on("tools/pre-execute", ...)：waterfall，返回 PreToolDecision ——
//     {kind:"deny",reason} | {kind:"ask",reason} | {kind:"cancel"} | {kind:"allow"}。
//     字段名是 reason（不是 question）；缺审批支持时 ask 自动降级为拒绝。
//     用它承载 ask/review：guard 表达不出"问人"。
//   · 两个通道会各跑一次同一个动作 ⇒ 必须按 callId 记忆化，否则同一动作在账本里落两行。
//   · 工具定义直接喂裸对象给 ctx.tools.register（已装插件 dsh-mnemon 即此写法），
//     且必须带 output.schema 与 output.render —— defineTool 无条件读 options.output.render，
//     缺了整条插件不激活（本次实测就是这样炸的）。
// 本文件【不含】任何凭证签发路径；签发只在 scripts/issue-grant.mjs（宿主侧 CLI）。
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadRules } from "./rules.js";
import { createEngine } from "./engine.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES = process.env.ACTION_GATE_RULES || path.join(HERE, "..", "rules", "default.json");
const DEFAULT_LEDGER = process.env.ACTION_GATE_LEDGER || path.join(HERE, "..", ".action-gate", "ledger.jsonl");

export const name = "action-gate";
export const description = "确定性动作闸门：执行前按规则裁决 allow/deny/review/ask，凭证由宿主签发，裁决只追加入账";
export const inject = ["tools"];

export async function apply(ctx, config = {}) {
  // config.rules / config.ledger：叠加层传了就赢；相对路径按【本包目录】解析，
  // 不是 process.cwd()——宿主的工作区到处变，锚在包目录才是确定的。
  const resolveCfg = (v, fallback) =>
    !v ? fallback : (path.isAbsolute(v) ? v : path.resolve(HERE, "..", v));
  const RULES = resolveCfg(config.rules, DEFAULT_RULES);
  const LEDGER = resolveCfg(config.ledger, DEFAULT_LEDGER);
  const rules = loadRules(RULES);
  const grants = (process.env.ACTION_GATE_GRANTS || "").split(";").map((s) => s.trim()).filter(Boolean);
  const engine = createEngine({ rules, ledgerFile: LEDGER, grants });

  // 一次动作只裁决一次、只落一行账：guard 与 pre-execute 共享这份记忆。
  const MEMO = new Map();
  const MEMO_CAP = 512;
  const decideOnce = (exec) => {
    const key = exec && exec.callId;
    if (!key) return engine.decide({ tool: exec && exec.name, args: exec && exec.arguments });
    const hit = MEMO.get(key);
    if (hit) return hit;
    if (MEMO.size >= MEMO_CAP) MEMO.delete(MEMO.keys().next().value);
    const d = engine.decide({ tool: exec.name, args: exec.arguments });
    MEMO.set(key, d);
    return d;
  };

  // ① 硬拒绝（权威通道，顺序无关、不可被后续钩子翻案）。
  if (typeof ctx.tools?.guard === "function") {
    ctx.effect(ctx.tools.guard((exec) => {
      const d = decideOnce(exec);
      return d.verdict === "deny" ? d.message : undefined;
    }), "action-gate:guard");
  }

  // ② 需要问人的裁决：guard 表达不出来，走 waterfall。
  // deny 在这里也返回一次，是为了让【拒绝理由】作为正规决策进入会话，而不只是事后错误文本。
  ctx.on("tools/pre-execute", async (exec, next) => {
    const d = decideOnce(exec);
    if (d.verdict === "deny") return { kind: "deny", reason: d.message };
    if (d.verdict === "ask" || d.verdict === "review") return { kind: "ask", reason: d.message };
    return next();
  });

  // ③ 三个只读自查工具：可查、可解释，结构上不产生授权（没有任何写路径）。
  // reg() 把 output.schema/render 一次性补齐，避免每个工具重复三遍。
  const reg = (name, description, properties, required, run) => ctx.tools.register({
    name,
    description,
    parameters: { type: "object", properties, ...(required ? { required } : {}), additionalProperties: false },
    // render 决定模型看到什么：必须把 value 序列化出去。写成常量文本会【整个吞掉】
    // execute 的返回值（2026-11-07 活宿主实测：gate_explain 只回 see result、verdict 全丢）。
    output: { schema: { type: "object", additionalProperties: true },
      render: (args, value) => [{ type: "text", text: JSON.stringify(value, null, 2) }] },
    execute: async (args) => run(args || {}),
  });

  reg("gate_status",
    "查当前动作闸门状态：生效规则 id、在线凭证（cls/scope/剩余次数）、账本路径。只读，不授权。",
    {}, null, () => engine.status());

  reg("gate_explain",
    "对一次【假想】动作跑闸门并返回完整求值轨迹（每条规则为何命中/未命中）。用于自查与调判据；不执行该动作、不落账、不授权。",
    { tool: { type: "string" }, args: { type: "object", additionalProperties: true } }, ["tool", "args"],
    (a) => { const x = engine.explain({ tool: a.tool, args: a.args }); return { subjects: x.subjects, hits: x.hits, trace: x.trace }; });

  reg("gate_audit",
    "读闸门账本最近 N 条裁决（含 verdict、rule_id、命中主体、凭证 jti）。账本只追加，不可改写。",
    { n: { type: "integer", minimum: 1, maximum: 500 } }, null,
    (a) => engine.audit(Number(a.n || 20)));

  // ④ 观察面 ≠ 授权面：执行结果只入账，永不参与裁决。
  ctx.on("tools/result", (exec, result) => {
    if (result && result.isError && engine.ledger) {
      engine.ledger.append({ verdict: "observed", stage: "post-failure", tool: exec && exec.name });
    }
  });

  ctx.logger?.info?.("[action-gate] 挂载完成：规则 " + rules.length + " 条，账本 " + LEDGER);
  console.log("[action-gate] 挂载完成：规则 " + rules.length + " 条，账本 " + LEDGER);
}
