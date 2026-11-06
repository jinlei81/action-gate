#!/usr/bin/env node
// 宿主侧凭证签发 CLI。模型不可达这条路径（它只出现在 scripts/，插件里没有注册任何调用它的工具）。
// 用法：
//   node scripts/issue-grant.mjs --cls write --scope /path/to/dir --uses 3 --minutes 15
// 密钥：环境变量 ACTION_GATE_GRANT_KEY，或文件 ~/.dsh/action-gate-grant.key
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { issueGrant } from "../src/grant.js";

const KEY_FILE = path.join(os.homedir(), ".dsh", "action-gate-grant.key");

function argv() {
  const out = {};
  const a = process.argv.slice(2);
  for (let i = 0; i < a.length; i++) {
    if (!a[i].startsWith("--")) continue;
    const k = a[i].slice(2);
    const v = a[i + 1] && !a[i + 1].startsWith("--") ? a[++i] : true;
    out[k] = v;
  }
  return out;
}

if (!process.env.ACTION_GATE_GRANT_KEY) {
  if (fs.existsSync(KEY_FILE)) process.env.ACTION_GATE_GRANT_KEY = fs.readFileSync(KEY_FILE, "utf8").trim();
  else { console.error("无签发密钥：设 ACTION_GATE_GRANT_KEY 或写 " + KEY_FILE + "（600 权限）"); process.exit(2); }
}
const o = argv();
if (!o.cls || !o.scope) { console.error("必填 --cls <write|destroy|net-send|read> --scope <路径前缀>"); process.exit(2); }
const minutes = Number(o.minutes || 15);
const tok = issueGrant({
  cls: String(o.cls),
  scope_prefix: String(o.scope),
  uses: Number(o.uses || 1),
  exp: Date.now() + minutes * 60_000,
  issued_by: o.issuedBy ? String(o.issuedBy) : os.userInfo().username + "@host",
  note: o.note ? String(o.note) : "",
});
console.log("grant=" + tok);
console.log("注入方式：启动宿主前设 ACTION_GATE_GRANTS="<tok>"（多条以 ; 分隔）");
