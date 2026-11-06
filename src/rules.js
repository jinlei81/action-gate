// 规则加载与匹配。规则文件用 JSON 而不是 YAML：解析器出错＝误拦或漏拦的源头，
// 宁可丑，不要静默误解。不认识的字段一律报错（防止规则悄悄失效）。
import fs from "node:fs";
import path from "node:path";
import { extractSubjects, flatten, isRootish, credentialishSubject } from "./subjects.js";

const ALLOWED_RULE_KEYS = new Set(["id", "action_class", "reason", "verdict", "when", "also", "unless"]);

const ALLOWED_PRED_KEYS = new Set(["tool", "tool_re", "subject_kind", "subject_re", "args_re", "subject_credentialish", "subject_rootish", "subject_outside", "subject_unresolved", "subject_absolute"]);

export function loadRules(file) {
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  if (raw.version !== 1) throw new Error("rules: 不支持的 version " + raw.version);
  if (!Array.isArray(raw.rules)) throw new Error("rules: rules 必须是数组");
  const seen = new Set();
  return raw.rules.map((r) => {
    for (const k of Object.keys(r)) if (!ALLOWED_RULE_KEYS.has(k)) throw new Error("规则 " + r.id + " 含未知字段 " + k);
    for (const seg of ["when", "also", "unless"]) {
      if (!r[seg]) continue;
      for (const k of Object.keys(r[seg])) if (!ALLOWED_PRED_KEYS.has(k)) throw new Error("规则 " + r.id + "." + seg + " 含未知判据 " + k);
    }
    if (!r.id) throw new Error("rules: 规则缺 id");
    if (seen.has(r.id)) throw new Error("rules: id 重复 " + r.id);
    seen.add(r.id);
    if (!["deny", "review", "ask"].includes(r.verdict)) throw new Error("规则 " + r.id + " verdict 非法: " + r.verdict);
    if (!r.reason) throw new Error("规则 " + r.id + " 缺 reason（拦住必须可解释）");
    return r;
  });
}

function re(pattern) {
  if (!(pattern instanceof RegExp)) return new RegExp(pattern, "i");
  return pattern;
}

// 谓词求值 ⇒ { hit: bool, why: string }
function pred(p, action, subjects) {
  const why = [];
  let matchedSubject = null; // 真正满足判据的主体：报它就是报触发者，不是第一个同型主体
  if (p.tool) {
    const names = Array.isArray(p.tool) ? p.tool : [p.tool];
    if (!names.includes(action.tool)) return { hit: false, why: "tool 不在列" };
    why.push("tool=" + action.tool);
  }
  if (p.tool_re) {
    if (!re(p.tool_re).test(String(action.tool))) return { hit: false, why: "tool_re 不匹" };
    why.push("tool_re");
  }
  let scoped = subjects;
  if (p.subject_kind) {
    const kinds = Array.isArray(p.subject_kind) ? p.subject_kind : [p.subject_kind];
    scoped = subjects.filter((x) => kinds.includes(x.kind));
    if (!scoped.length) return { hit: false, why: "无该型主体" };
    why.push("subject_kind=" + kinds.join("/"));
  }
  if (p.subject_re) {
    const rx = re(p.subject_re);
    const s = scoped.find((x) => rx.test(x.value));
    if (!s) return { hit: false, why: "subject_re 不匹" };
    matchedSubject = s;
    why.push("subject_re 匹中 " + brief(s.value));
  }
  if (p.subject_rootish) {
    const cands = scoped.length ? scoped : subjects.filter((x) => x.kind === "destroy-target" || x.kind === "path");
    const s = cands.find((x) => isRootish(x.expanded || x.value));
    if (!s) return { hit: false, why: "宾语不是根形态" };
    matchedSubject = s;
    why.push("rootish 宾语 " + brief(s.value));
  }
  if (p.subject_credentialish) {
    // 结构化判据（paths.isCredentialish2）：只看文件名与环境变量名，不匹 URL 全文。
    // 旧的 /token/i.test(URL) 会把插件页 .../dsh-plugin-save-token/ 误判成凭据出境。
    const s = scoped.find((x) => credentialishSubject(x));
    if (!s) return { hit: false, why: "无凭据形态主体" };
    matchedSubject = s;
    why.push("凭据形态主体 " + s.kind + ":" + brief(s.value));
  }
  if (p.subject_outside) {
    // 正面证据：解析成绝对路径且确在工作区/临时区之外。没有它就不许 deny。
    const s = scoped.find((x) => x.out === true);
    if (!s) return { hit: false, why: "无「绝对且在工作区外」的正面证据" };
    matchedSubject = s;
    why.push("工作区外 " + brief(s.expanded || s.value));
  }
  if (p.subject_unresolved) {
    // 判据不完备：宾语是变量套变量之类，说不清删到哪。
    const s = scoped.find((x) => x.resolved === false);
    if (!s) return { hit: false, why: "主体都能解析" };
    matchedSubject = s;
    why.push("宾语解析不出 " + brief(s.value));
  }
  if (p.subject_absolute) {
    const s = scoped.find((x) => x.absolute === true);
    if (!s) return { hit: false, why: "无绝对形态主体" };
    matchedSubject = s;
    why.push("绝对形态 " + brief(s.value));
  }
  if (p.args_re) {
    if (!re(p.args_re).test(flatten(action.args || {}))) return { hit: false, why: "args_re 不匹" };
    why.push("args_re");
  }
  return { hit: true, why: why.join(" & "), subject: matchedSubject };
}

function brief(v) {
  const s = String(v);
  return s.length > 48 ? s.slice(0, 48) + "..." : s;
}

// ⇒ { matched, verdict, rule, predicates, subject }
export function matchRule(rule, action, subjects) {
  const when = pred(rule.when || {}, action, subjects);
  if (!when.hit) return { matched: false, whyNot: when.why };
  // §3 语义：when 定主体范围，also/unless 只在这个范围【内】加条件。
  // 不继承就会拿 also 的正则去打 op-destroy 全文（它以 "rm -rf" 开头）⇒ 误拦。
  const inherit = rule.when && rule.when.subject_kind ? { subject_kind: rule.when.subject_kind } : {};
  const alsoP = rule.also ? Object.assign({}, inherit, rule.also) : null;
  const unlessP = rule.unless ? Object.assign({}, inherit, rule.unless) : null;
  let also = null;
  if (alsoP) {
    also = pred(alsoP, action, subjects);
    if (!also.hit) return { matched: false, whyNot: "also 未成立: " + also.why };
  }
  if (unlessP) {
    const u = pred(unlessP, action, subjects);
    if (u.hit) return { matched: false, whyNot: "unless 命中(视为误拦出口): " + u.why };
  }
  const ps = [when];
  if (also) ps.push(also);
  // 报告主体＝触发判据的那个主体。旧实现取第一个同型主体，于是消息指着
  // $ErrorActionPreference 而真正让它响的是同一命令里的 $env:GITHUB_TOKEN ⇒ 解释在撒谎。
  const kinds = rule.when && rule.when.subject_kind ? [].concat(rule.when.subject_kind) : null;
  const target = when.subject
    || (also && also.subject)
    || (kinds ? subjects.find((s) => kinds.includes(s.kind)) : null)
    || subjects[0] || null;
  return {
    matched: true,
    verdict: rule.verdict,
    rule_id: rule.id,
    action_class: rule.action_class || "any",
    reason: rule.reason,
    predicate: ps.map((x) => x.why).join(" ; "),
    subject: target ? { kind: target.kind, value: target.value, field: target.field } : null,
  };
}

export function inspect(action, rules) {
  const subjects = extractSubjects(action);
  const hits = [];
  for (const r of rules) {
    const m = matchRule(r, action, subjects);
    if (m.matched) hits.push(m);
  }
  return { subjects, hits };
}
