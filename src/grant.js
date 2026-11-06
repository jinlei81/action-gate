// 动作凭证（grant）：宿主签发、模型不可自签的一次性放行凭据。
// 关键设计：本模块【不】在插件里暴露任何签发入口。签发只能由宿主侧代码
// 或进程环境变量完成 ⇒ 被审计的一方拿不到造凭据的能力。
import crypto from "node:crypto";
import fs from "node:fs";

const KEY_ENV = "ACTION_GATE_GRANT_KEY";
const KEY_FILE = process.env.ACTION_GATE_GRANT_KEY_FILE || "";

function loadKey() {
  const fromEnv = process.env[KEY_ENV];
  if (fromEnv && fromEnv.length >= 16) return Buffer.from(fromEnv, "utf8");
  if (KEY_FILE && fs.existsSync(KEY_FILE)) {
    const k = fs.readFileSync(KEY_FILE, "utf8").trim();
    if (k.length >= 16) return Buffer.from(k, "utf8");
  }
  return null;
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64url(s) {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(t + "=".repeat((4 - (t.length % 4)) % 4), "base64");
}
function sign(payloadB64, key) {
  return crypto.createHmac("sha256", key).update(payloadB64).digest("hex");
}

// 仅宿主侧调用；插件不注册任何调用它的工具。
export function issueGrant(payload) {
  const key = loadKey();
  if (!key) throw new Error("grant: 无签发密钥（设 " + KEY_ENV + " 或 ACTION_GATE_GRANT_KEY_FILE）");
  const p = {
    cls: String(payload.cls),                    // 放行的动作类，如 write / destroy / net-send
    scope_prefix: String(payload.scope_prefix),  // 只在该前缀内有效
    uses: Math.max(1, Number(payload.uses || 1)),
    exp: Number(payload.exp || Date.now() + 15 * 60 * 1000),
    issued_by: String(payload.issued_by || "host"),
    note: String(payload.note || ""),
    jti: crypto.randomUUID(),
  };
  const body = b64url(JSON.stringify(p));
  return body + "." + sign(body, key);
}

export function verifyGrant(token, keyOverride) {
  const key = keyOverride || loadKey();
  if (!key) return { ok: false, reason: "no-key" };
  const i = String(token || "").lastIndexOf(".");
  if (i <= 0) return { ok: false, reason: "malformed" };
  const body = token.slice(0, i);
  const mac = token.slice(i + 1);
  const expect = sign(body, key);
  const a = Buffer.from(mac, "hex");
  const b = Buffer.from(expect, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: "bad-signature" };
  let p;
  try { p = JSON.parse(unb64url(body).toString("utf8")); } catch { return { ok: false, reason: "bad-payload" }; }
  if (typeof p.exp !== "number" || p.exp < Date.now()) return { ok: false, reason: "expired" };
  if (typeof p.uses !== "number" || p.uses < 1) return { ok: false, reason: "spent" };
  return { ok: true, payload: p };
}

// 凭证覆盖判定：cls 要对，且被拦主体必须落在 scope_prefix 内。
export function grantCovers(grantPayload, rule, subject) {
  if (!grantPayload || !rule) return { covers: false, reason: "no-grant" };
  const cls = rule.action_class || "any";
  if (grantPayload.cls !== cls && grantPayload.cls !== "any") return { covers: false, reason: "cls-mismatch" };
  const value = subject ? String(subject.value) : "";
  const prefix = String(grantPayload.scope_prefix || "");
  if (!prefix) return { covers: false, reason: "empty-scope" };
  if (prefix !== "/" && !value.toLowerCase().startsWith(prefix.toLowerCase())) {
    // 允许 scope 匹主体里的任意路径片段（宿主更常按目录前缀签）
    const segs = value.split(/[\\/]/).filter(Boolean);
    if (!segs.some((s) => s.toLowerCase() === prefix.toLowerCase().replace(/^[\\/]+/, ""))) {
      return { covers: false, reason: "scope-mismatch" };
    }
  }
  return { covers: true, reason: "scope=" + prefix };
}
