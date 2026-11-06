// 裁决核心：规则命中 × 凭证覆盖 × 账本入账。
import { inspect } from "./rules.js";
import { verifyGrant, grantCovers } from "./grant.js";
import { makeLedger } from "./ledger.js";

export function createEngine({ rules, ledgerFile, grants = [] }) {
  const ledger = ledgerFile ? makeLedger(ledgerFile) : null;
  const spent = new Map(); // jti -> 剩余次数

  function liveGrants() {
    const out = [];
    for (const tok of grants) {
      const v = verifyGrant(tok);
      if (!v.ok) continue;
      const left = spent.has(v.payload.jti) ? spent.get(v.payload.jti) : v.payload.uses;
      if (left < 1) continue;
      out.push({ token: tok, payload: v.payload, left });
    }
    return out;
  }

  function decide(action) {
    const { subjects, hits } = inspect(action, rules);
    const deny = hits.find((h) => h.verdict === "deny");
    const review = hits.find((h) => h.verdict === "review");
    const ask = hits.find((h) => h.verdict === "ask");
    const base = { tool: action.tool, subjects, hits };

    if (deny) {
      const g = liveGrants().find((x) => grantCovers(x.payload, deny, deny.subject).covers);
      if (g) {
        spent.set(g.payload.jti, g.left - 1);
        const rec = { verdict: "allow", via: "grant", rule_id: deny.rule_id, grant_jti: g.payload.jti, predicate: deny.predicate, subject: deny.subject, action_class: deny.action_class };
        if (ledger) ledger.append(rec);
        return { ...base, verdict: "allow", via: "grant", rule: deny, grant: g.payload };
      }
      const rec = { verdict: "deny", rule_id: deny.rule_id, predicate: deny.predicate, subject: deny.subject, action_class: deny.action_class, reason: deny.reason };
      if (ledger) ledger.append(rec);
      return { ...base, verdict: "deny", rule: deny, message: "[action-gate·" + deny.rule_id + "] " + deny.reason + "｜主体=" + (deny.subject ? deny.subject.kind + ":" + deny.subject.value : "n/a") + "｜判据=" + deny.predicate };
    }
    const soft = review || ask;
    if (soft) {
      const rec = { verdict: soft.verdict, rule_id: soft.rule_id, predicate: soft.predicate, subject: soft.subject, action_class: soft.action_class, reason: soft.reason };
      if (ledger) ledger.append(rec);
      return { ...base, verdict: soft.verdict, rule: soft, message: "[action-gate·" + soft.rule_id + "] 判据不完备，交人：" + soft.reason };
    }
    const rec = { verdict: "allow", rule_id: null, subject_count: subjects.length };
    if (ledger) ledger.append(rec);
    return { ...base, verdict: "allow", rule: null };
  }

  return {
    decide,
    ledger,
    // 只读面：可查、可解释，永不授权。
    status() {
      return { rules: rules.length, rule_ids: rules.map((r) => r.id), grants_live: liveGrants().map((g) => ({ jti: g.payload.jti, cls: g.payload.cls, scope: g.payload.scope_prefix, left: g.left, issued_by: g.payload.issued_by })), ledger: ledger ? ledger.file : null };
    },
    explain(action) {
      const { subjects, hits } = inspect(action, rules);
      const trace = rules.map((r) => {
        const m = inspect({ tool: action.tool, args: action.args }, [r]);
        return { id: r.id, matched: m.hits.length > 0, why: m.hits[0] ? m.hits[0].predicate : (m.subjects.length ? "未命中" : "无主体") };
      });
      return { subjects, hits, trace };
    },
    audit(n = 20) {
      if (!ledger) return { rows: [], note: "无账本" };
      const rows = ledger.readAll();
      return { total: rows.length, shown: Math.min(n, rows.length), rows: rows.slice(-n) };
    },
  };
}
