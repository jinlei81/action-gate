// DSH 插件入口。
// 机制选型（已对宿主 app.asar 的扩展点说明核对，asar:352803-352810）：
//   · 无视挂载顺序必须成立【只拒不改】⇒ ctx.tools.guard()（同步）
//   · 需要问人 ⇒ 从 tools/pre-execute 返回 ask
//   · 纯观察入账 ⇒ tools/result
// 本文件【不含】任何凭证签发路径；签发只在 scripts/issue-grant.mjs（宿主侧 CLI）。
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadRules } from "./rules.js";
import { createEngine } from "./engine.js";

let defineTool;
try { ({ defineTool } = await import("@deepseek-ai/dsh-tools")); } catch { defineTool = null; }

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES = process.env.ACTION_GATE_RULES || path.join(HERE, "..", "rules", "default.json");
const DEFAULT_LEDGER = process.env.ACTION_GATE_LEDGER || path.join(HERE, "..", ".action-gate", "ledger.jsonl");

export const name = "action-gate";
export const description = "确定性动作闸门：执行前按规则裁决 allow/deny/review/ask，凭证由宿主签发，裁决只追加入账";
export const inject = ["tools"];

export async function apply(ctx) {
  const rules = loadRules(DEFAULT_RULES);
  const grants = (process.env.ACTION_GATE_GRANTS || "").split(";").map((s) => s.trim()).filter(Boolean);
  const engine = createEngine({ rules, ledgerFile: DEFAULT_LEDGER, grants });

  // ① 硬拒绝：同步、与挂载顺序无关 ⇒ guard。命中 deny 就回绝，不带改写能力。
  if (typeof ctx.tools?.guard === "function") {
    ctx.tools.guard((exec) => {
      const decision = engine.decide({ tool: exec?.name, args: exec?.arguments });
      if (decision.verdict === "deny") return { deny: decision.message };
      return undefined;
    });
  } else {
    ctx.on("tools/pre-execute", async (exec, next) => {
      const decision = engine.decide({ tool: exec?.name, args: exec?.arguments });
      if (decision.verdict === "deny") return { kind: "deny", reason: decision.message };
      if (decision.verdict === "ask" || decision.verdict === "review") return { kind: "ask", question: decision.message };
      return next();
    });
  }

  // ② 只读三个自查工具：可查、可解释，结构上不产生授权。
  const T = defineTool || ((d) => d);
  ctx.tools.register(T({
    name: "gate_status",
    description: "查当前动作闸门状态：生效规则 id、在线凭证（cls/scope/剩余次数）、账本路径。只读，不授权。",
    parameters: { type: "object", properties: {} },
    async execute() { return JSON.stringify(engine.status(), null, 2); },
  }));
  ctx.tools.register(T({
    name: "gate_explain",
    description: "对一次【假想】动作跑闸门并返回完整求值轨迹（每条规则为何命中/未命中）。用于自查与调判据；不执行该动作、不授权。",
    parameters: {
      type: "object",
      properties: { tool: { type: "string" }, args: { type: "object" } },
      required: ["tool", "args"],
    },
    async execute(params) {
      const d = engine.decide({ tool: params.tool, args: params.args || {} });
      return JSON.stringify({ verdict: d.verdict, rule_id: d.rule ? d.rule.rule_id : null, trace: engine.explain({ tool: params.tool, args: params.args || {} }).trace }, null, 2);
    },
  }));
  ctx.tools.register(T({
    name: "gate_audit",
    description: "读闸门账本最近 N 条裁决（含 verdict、rule_id、命中主体、凭证 jti）。只追加，不可改写。",
    parameters: { type: "object", properties: { n: { type: "number" } } },
    async execute(params) { return JSON.stringify(engine.audit(Number(params?.n || 20)), null, 2); },
  }));

  // ③ 观察面：执行结果只入账，不参与裁决，永不授权。
  ctx.on("tools/result", (exec, result) => {
    if (result && result.isError) engine.ledger && engine.ledger.append({ verdict: "observed", stage: "post-failure", tool: exec && exec.name });
  });

  ctx.on("agent/pre-step", async (payload, next) => next());
  console.log("[action-gate] 挂载完成：规则 " + rules.length + " 条，账本 " + DEFAULT_LEDGER);
}
