// 路径解析与字段角色。存在的理由：回放器实测误拦率 85%，四条根因都在这句上——
// 「解析不出绝对路径」被当成了「在工作区外」。
// 原则：deny 必须有正面证据（解析出的绝对路径且确实在工作区之外）；
// 判据不完备就退回 allow 或 review，绝不靠猜去 deny。
import os from "node:os";
import path from "node:path";

// 本文件正文不含反斜杠字符（多层转义把内容写错，是本项目反复踩的坑）
const B = String.fromCharCode(92);
const D = String.fromCharCode(36);

// 参数分两类角色。数据字段里的英文单词不是命令：
// 实测 tool=write 写一篇文档，正文含 del C:\XO2\data\back 就被判成删除动作。
export const DATA_FIELDS = new Set([
  "content", "text", "body", "old_string", "new_string", "plan", "answer",
  "message", "summary", "description", "justification", "title", "prompt",
  "objective", "reason", "note", "snippet", "custom"
]);

export function fieldRole(field) {
  return DATA_FIELDS.has(String(field)) ? "data" : "command";
}

// D（美元符）必须进 [$] 字符类：留在外面就是行尾锚点，三条展开正则曾因此集体空转
const RX_ENV_PS = new RegExp("[" + D + "]env:([A-Za-z_][A-Za-z0-9_]*)", "g");
const RX_ENV_BRACE = new RegExp("[" + D + "][{]([A-Za-z_][A-Za-z0-9_]*)[}]", "g");
const RX_ENV_CMD = new RegExp("%([A-Za-z_][A-Za-z0-9_]*)%", "g");
// 残留变量标记：展开成功后不该再有 $。
// 不用正则——$ 在字符类外是行尾锚点，嵌套字符类今天已两次把我炸穿；字面扫描更简单也更难写错。
const RX_PERCENT = new RegExp("%[A-Za-z_][A-Za-z0-9_]*%");

function hasResidue(s) {
  if (s.indexOf(D) !== -1) return true;
  if (RX_PERCENT.test(s)) return true;
  return false;
}

// $env:X / ${X} / %X% / ~ 展开。展开不了（如 $w 后接 $f）⇒ 原样返回并标记未解析。
export function expandVars(s) {
  let out = String(s);
  let dirty = false;
  const sub = (m, k) => {
    const v = process.env[k];
    if (v === undefined) { dirty = true; return m; }
    return v;
  };
  out = out.replace(RX_ENV_PS, sub);
  out = out.replace(RX_ENV_BRACE, sub);
  out = out.replace(RX_ENV_CMD, sub);
  if (out === "~" || out.startsWith("~/") || out.startsWith("~" + B)) {
    const home = process.env.HOME || process.env.USERPROFILE || "";
    if (home) out = home + out.slice(1);
    else dirty = true;
  }
  if (hasResidue(out)) dirty = true;
  return { value: out, resolved: !dirty };
}

const RX_DRIVE = /^[A-Za-z]:/;

// 绝对形态：盘符根 / UNC / unix 根。相对路径与残留变量都不算。
export function isAbsoluteShape(s) {
  const v = String(s).trim();
  if (!v) return false;
  if (v.startsWith("/")) return true;
  if (v.startsWith(B + B)) return true;
  // X:// 是 URL 残片不是本地盘路径（URL 已在前一层挖除，这里再兜一道）
  if (/^[A-Za-z]:\/\//.test(v)) return false;
  if (RX_DRIVE.test(v)) {
    const c = v.charAt(2);
    return c === "" || c === B || c === "/";
  }
  return false;
}

// 散文不是路径：实测引号捕获把 write FAIL: $($_.Exception.Message) 当成了删除宾语。
export function looksPathish(s) {
  const v = String(s).trim();
  if (!v) return false;
  if (v.includes(D + "(") || v.includes("`")) return false;
  if (/[<>|&]/.test(v)) return false;
  if (v.includes(B + B) === false && RX_DRIVE.test(v) === false && !v.startsWith("/") && v.includes(":")) return false;
  const abs = isAbsoluteShape(v);
  const glob = v.includes("*") || v.includes("?");
  if (/\s/.test(v) === false) return true;
  if (abs || glob) return true;
  return false;
}

const CRED_EXT = [".yaml", ".yml", ".json", ".pem", ".key", ".p12", ".pfx", ".env", ".netrc", ".kdbx"];
const CRED_WORD = ["credential", "secret", "passwd", "password", "token", "apikey", "api_key", "access_key", "private", "id_rsa", "id_ed25519", "netrc", "vault"];
// 按分隔符边界匹，不用裸 "KEY"：实测 level_keyword / keyword 被当成凭据 ⇒ 出境规则假阳性 4 次
const ENV_CRED_WORD = ["TOKEN", "SECRET", "PASSWD", "PASSWORD", "APIKEY", "API_KEY", "ACCESS_KEY", "ACCESSKEY", "CREDENTIAL", "PRIVATE", "CLIENT_SECRET", "CLIENTSECRET", "REFRESH_TOKEN", "SIGNATURE", "_PAT", "PAT_", "KEY_ID", "KEYID"];

// 绝不因解码失败而崩：崩掉＝整条裁决链失效＝无声放过，比误拦更坏
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return String(s); }
}
// 变量名/query key 里的凭据语义词：以分隔符或串首尾为界，故 LEVEL_KEYWORD 不算
function credKeyToken(up) {
  const s = String(up || "");
  for (const w of ENV_CRED_WORD) {
    const t = w.replace(/[_]/g, "_");
    const re = new RegExp("(^|[^A-Z0-9])" + t + "($|[^A-Z0-9])");
    if (re.test(s)) return true;
    // 曾有 `s.includes(t)` 特例 ⇒ "_PAT" 匹进 NODE_PATH 中段（实测假 deny 2 次）。边界正则已覆盖 ACCESS_KEY_ID 之类，特例删掉。
  }
  const parts = s.split(/[^A-Z0-9]+/);
  for (const p of parts) if (p === "KEY" || p === "PAT" || p === "SECRET" || p === "TOKEN") return true;
  return false;
}

function baseName(v) {
  const parts = String(v).split("/").join(B + B).split(B);
  for (let i = parts.length - 1; i >= 0; i--) if (parts[i]) return parts[i];
  return "";
}

function nameIsCred(base) {
  const b = base.toLowerCase();
  let word = false;
  for (const w of CRED_WORD) if (b.includes(w)) { word = true; break; }
  if (!word) return false;
  for (const e of CRED_EXT) if (b.endsWith(e)) return true;
  if (b === ".env" || b.startsWith(".env.")) return true;
  if (b.startsWith("id_rsa") || b.startsWith("id_ed25519")) return true;
  return false;
}

// 凭据判据只看【文件名与环境变量名】。
// 旧实现拿正则打 URL 全文，于是插件页 .../dsh-plugin-save-token/ 被误拦：
// 路径里出现 token 这个词，不构成凭据证据。
export function isCredentialish2(kind, value) {
  const v = String(value || "");
  if (!v) return false;
  if (kind === "env") {
    const up = v.toUpperCase();
    if (credKeyToken(up)) return true;
    return false;
  }
  if (kind === "url") {
    // 只有两种情形算出境证据：query/fragment 里带着绝对路径的凭据文件名，或 query 里 key=值 的 key 是凭据名
    const q = v.includes("?") ? v.slice(v.indexOf("?") + 1) : (v.includes("#") ? v.slice(v.indexOf("#") + 1) : "");
    if (!q) return false;
    for (const seg of q.split(/[&=;]/)) {
      const s = safeDecode(seg);
      if (isCredentialish2("path", s)) return true;
      if (s.includes("=")) continue;
    }
    const kv = q.split("&");
    for (const pair of kv) {
      const k = pair.split("=")[0];
      const ku = safeDecode(k).toUpperCase();
      if (credKeyToken(ku)) return true;
    }
    return false;
  }
  if (kind === "host") return false;
  if (kind === "path" || kind === "destroy-target" || kind === "cmd" || kind === "op-destroy" || kind === "op-write") {
    const slashed = String(v).split(B).join("/");
    if (/\.ssh\//.test("/" + slashed.replace(/^[A-Za-z]:/, "/"))) {
      if (slashed.includes("/.ssh/")) return true;
    }
    if (nameIsCred(baseName(v))) return true;
    return false;
  }
  return false;
}

function splitList(raw) {
  return String(raw || "").split(";").map((s) => s.trim()).filter(Boolean);
}

// 工作区根从环境读，绝不把某台机器的路径硬编码进规则：
// 没设就退回进程当前目录（插件的 cwd 就是会话工作区）。
export function workspaceRoots() {
  const raw = process.env.ACTION_GATE_WORKSPACE || "";
  const list = splitList(raw);
  if (list.length) return list;
  return [process.cwd()];
}

// 临时区与构建产物：删这些是日常，不算越界。
export function scratchRoots() {
  // 必须含 os.tmpdir()：宿主里 TEMP 有值，但回放/子进程 env 可能整个是空的。
  // 少这一条会把 C:\...\Temp\x 判成「工作区外」⇒ 越界 deny 虚高（实测虚增到 176 条）。
  const t = [
    process.env.TEMP,
    process.env.TMP,
    process.env.LOCALAPPDATA ? process.env.LOCALAPPDATA + B + "Temp" : "",
    (() => { try { return os.tmpdir(); } catch { return ""; } })(),
    (() => { try { return path.join(os.homedir(), "AppData", "Local", "Temp"); } catch { return ""; } })()
  ].filter(Boolean);
  return splitList(process.env.ACTION_GATE_SCRATCH).concat(t).concat(["/tmp"]);
}

export function insideAny(candidate, roots) {
  if (!candidate || !isAbsoluteShape(candidate)) return false;
  let c;
  try { c = path.resolve(candidate).toLowerCase(); } catch { return false; }
  for (const r of roots) {
    let rr;
    try { rr = path.resolve(r).toLowerCase(); } catch { continue; }
    if (!rr) continue;
    if (c === rr) return true;
    const sep = rr.slice(-1) === B || rr.slice(-1) === "/" ? rr : rr + B;
    if (c.startsWith(sep)) return true;
  }
  return false;
}

// ⇒ { out, resolved, why, value }。out 为真必须有正面证据：绝对、且不在工作区/临时区内。
// 设备/重定向汇：`> /dev/null`、`2>NUL` 在命令里到处出现，它们永远不是删除目标，
// 也不是「系统树根目录」（实测 /dev/null 被当删除宾语 deny 10 次）。
const DEVICE_SINK = new Set(["/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr",
  "/dev/zero", "/dev/random", "/dev/urandom", "nul", "\\/.\\/nul"]);
export function isDeviceSink(v) {
  const s = String(v || "").trim().toLowerCase().replace(/^['"]|['"]$/g, "");
  if (!s) return false;
  return DEVICE_SINK.has(s) || DEVICE_SINK.has(s.replace(/\\/g, "/"));
}

// 只有一个分段、且以分隔符开头（\dsh-hf3.sh、/foo）：真正的根是【当前盘/当前目录】，
// 而当前盘随宿主 cwd 变 ⇒ 解析不出确定目标。这种形态不许当成「绝对且在工作区外」的正面证据。
export function isFragmentaryRoot(v) {
  const s = String(v || "").trim().replace(/^['"]|['"]$/g, "");
  if (!/^[\\/]/.test(s)) return false;
  if (/^[\\/]{2,}$/.test(s)) return false;           // // 或 \\ 就是根本身，不算片段
  const segs = s.split(/[\\/]+/).filter(Boolean);
  return segs.length <= 1;
}

export function outsideWorkspace(value) {
  const exp = expandVars(value);
  if (isDeviceSink(value)) return { out: false, resolved: true, why: "设备/重定向汇，不是目标", value: String(value) };
  if (isFragmentaryRoot(value)) return { out: false, resolved: false, why: "单段根相对片段，确定不了挂在哪个根", value: String(value).trim() };
  // 盘根（C: 或 C:\）：path.resolve 会把它解析成「该盘当前目录」⇒ 工作区在 C: 上就误判成区内（实测漏拦 rm -rf C:\）,  if (/^[A-Za-z]:[\\/]*$/.test(String(value).trim())) return { out: true, resolved: true, why: "整块盘根", value: String(value).trim() };
  if (!isAbsoluteShape(exp.value)) return { out: false, resolved: false, why: "解析不出绝对路径", value: exp.value };
  if (insideAny(exp.value, workspaceRoots())) return { out: false, resolved: true, why: "在工作区内", value: exp.value };
  if (insideAny(exp.value, scratchRoots())) return { out: false, resolved: true, why: "在临时区内", value: exp.value };
  return { out: true, resolved: true, why: "绝对且在工作区外", value: exp.value };
}

// 未解析的宾语（$w\$f 之类）：判据不完备 ⇒ 交人，不 deny
export function isUnresolvedTarget(value) {
  const exp = expandVars(value);
  return !exp.resolved || !isAbsoluteShape(exp.value);
}
