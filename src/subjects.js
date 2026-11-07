// 主体提取：从一次动作的参数里解析出「被作用的对象」。规则匹对象，不匹文本距离。
// 这一层是判据的地基：文本距离既漏真动作，又误伤纯字符串说明。
//
// 实测教训（回放器 4000 条真实调用，误拦率 85%，四条根因都在本层）：
//   ① 数据字段（write 的 content）里的英文不是命令 ⇒ 由 paths.fieldRole 分流；
//   ② 引号捕获会把散文当成宾语（"write FAIL: $($_.Exception.Message)"）⇒ looksPathish 筛掉；
//   ③ 解析不出绝对路径不等于在工作区外 ⇒ 主体带 resolved/outside 标记，交给规则层判；
//   ④ URL 里出现 token 这个词不算凭据 ⇒ 判据移到 paths.isCredentialish2。
import { fieldRole, looksPathish, expandVars, isAbsoluteShape, outsideWorkspace, isCredentialish2 , isDeviceSink } from "./paths.js";

export const URL_RE = /https?:\/\/[^\s"'<>|]+/gi;
export const PATH_WIN_ROOT = /[A-Za-z]:[\\/]/g;
// 盘符前不得是字母数字：否则 Remove-Item Env:\TRAE_DRYRUN 里的 "v:\TRAE_DRYRUN" 会被当路径（实测误拦）
export const PATH_WIN = /(?<![\w])([A-Za-z]:[\\/][^\s"'<>|]+)/g;
export const PATH_UNIX = /\/(?:Users|home|etc|var|opt|tmp|srv|mnt|usr|root|dev|proc|sys|bin|sbin|lib|boot|\.dsh|\.ssh)[^\s"'<>|]*/g;
export const BARE_ROOT = /(?:^|[\s"'(,=])(\/+|\*|~\/?|\$HOME\/?|%USERPROFILE%)(?=$|[\s"'(),;])/g;
// 环境变量必须【显式】：PowerShell 的 $env:X / ${env:X}、cmd 的 %X%。
// 旧正则把 env: 写成可选，于是 $token（PS 局部变量）被当环境变量 ⇒ 实测 42 次假 deny。
export const ENV_RE = /\$\{?env:([A-Za-z_][A-Za-z0-9_]{2,})\}?|%([A-Z][A-Z0-9_]{2,})%|\$\((?:printenv|env)[^)]*\)\s*([A-Z_][A-Z0-9_]{2,})/gi;
// bash 的 $NAME 分不清是环境变量还是 shell 局部变量 ⇒ 另立一类，只许 review，不许 deny。
export const VAR_RE = /\$\{?([A-Z][A-Z0-9_]{2,})\}?/g;
export const DESTROY_RE = /\b(Remove-Item|Remove-ItemProperty|Remove|rmdir|rm|del|erase|unlink|shred|mv|Move-Item|format|DROP\s+TABLE|DELETE\s+FROM|Clear-Disk)\b/;
export const WRITE_RE = /\b(Out-File|Set-Content|Add-Content|writeFile|writeFileSync|appendFile|WriteAllText|WriteAllBytes|copy)\b/i;
export const SEND_RE = /\b(Invoke-RestMethod|Invoke-WebRequest|curl|wget|fetch|Upload|POST|PUT|Send-MailMessage)\b/i;
export const CRED_RE = /(credential|secret|token|password|passwd|api[_-]?key|access[_-]?token|private[_-]?key|\.credentials|id_rsa|id_ed25519|\.netrc)/i;
// 递归删除的开关只认这几种写法。宽式 -[a-zA-Z]*r[a-zA-Z]* 会把 -Uri 也算递归（实测造出假主体）。
export const RECURSE_RE = /\brm\s+(?:-\w+\s+)*-(?:rf|fr|fr[\w]*|r|recursive|Recurse)\b|\bRemove-Item\b[^\r\n]*-Recurse\b|\bdel\s+\/s\b|\brmdir\s+\/s\b|\bshred\s+-[a-zA-Z]*r\b/i;

export function flatten(v, depth = 0) {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (depth > 4) return "";
  // 数组是 argv 形态 ⇒ 用空格拼（用换行会把动词和宾语切到两行，宾语解析失效）
  if (Array.isArray(v)) return v.map((x) => flatten(x, depth + 1)).join(" ");
  return Object.values(v).map((x) => flatten(x, depth + 1)).join("\n");
}

function norm(s) {
  const v = String(s).replace(/[\\/]+$/, "").replace(/\s+$/, "").trim();
  // 斜杠根与盘根本身就是目标，剥尾分隔符会把它们剥成空串（实测 rm -rf / 因此丢主体）
  if (!v && /^[\\/]+$/.test(String(s).trim())) return String(s).trim();
  if (!v && /^[A-Za-z]:$/.test(String(s).trim())) return String(s).trim();
  return v;
}

// 一条路径主体的完整证据：原文 + 展开后 + 是否解析成功 + 是否确实在工作区外。
// 规则层要 deny 就必须拿 out=true（正面证据），拿不到就只能 review。
function pathSubject(kind, raw, field) {
  const v = norm(raw);
  if (!v) return null;
  const exp = expandVars(v);
  const o = outsideWorkspace(exp.value);
  return {
    kind,
    value: v,
    field,
    expanded: exp.value,
    resolved: exp.resolved,
    absolute: isAbsoluteShape(exp.value),
    out: o.out,
    where: o.why
  };
}

export function extractSubjects(action) {
  const out = [];
  const args = action && action.args ? action.args : {};
  for (const [field, raw] of Object.entries(args)) {
    const text = flatten(raw);
    if (!text) continue;
    const role = fieldRole(field);
    // 扫路径前先把 URL 整段挖掉。否则 https:// 会被盘符正则匹成 "s://evil..."，
    // 造出一个假 path 主体且被判成「绝对且在工作区外」⇒ 凭空编造出 deny 的正面证据。
    // URL 里的凭据证据仍由 url 主体本身承担（paths.isCredentialish2 看 query）。
    let pathText = text;
    for (const m of text.matchAll(URL_RE)) {
      if (m[0]) pathText = pathText.split(m[0]).join(" ");
    }
    // 数据字段（文档正文、描述、old/new_string…）不是命令：里面出现 rm 或路径都不构成动作。
    // 但仍抽 url/path/env 作为「内容里有什么」的观察面，供只读工具解释，不参与 op-* 判定。
    for (const m of text.matchAll(URL_RE)) {
      const u = pathSubject("url", m[0], field);
      if (u) out.push(u);
      let host = "";
      try { host = new URL(m[0]).hostname; } catch { host = ""; }
      if (host) out.push({ kind: "host", value: host, field });
    }
    for (const m of pathText.matchAll(PATH_WIN)) { const s = pathSubject("path", m[0], field); if (s) out.push(s); }
    for (const m of pathText.matchAll(PATH_UNIX)) { const s = pathSubject("path", m[0], field); if (s) out.push(s); }
    for (const m of text.matchAll(ENV_RE)) out.push({ kind: "env", value: (m[1] || m[2] || m[3] || "").toUpperCase(), field });
    for (const m of text.matchAll(VAR_RE)) out.push({ kind: "env-implicit", value: m[1], field });
    if (role !== "command") continue;
    if (DESTROY_RE.test(text)) {
      out.push({ kind: "op-destroy", value: text.slice(0, 160), field });
      for (const t of destroyTargets(pathText)) {
        const s = pathSubject("destroy-target", t, field);
        if (s) out.push(s);
      }
    }
    if (WRITE_RE.test(text)) out.push({ kind: "op-write", value: text.slice(0, 160), field });
    if (SEND_RE.test(text)) out.push({ kind: "op-send", value: text.slice(0, 160), field });
    if (RECURSE_RE.test(text)) out.push({ kind: "op-recurse", value: text.slice(0, 160), field });
  }
  return out;
}

// 删除/移动类：把动词宾语的片段单独取出来再判形态。
// 「Remove-Item C:\x\y.log」与「注释里写了 rm 这个词」在这里就分开了。
export function destroyTargets(text) {
  const found = [];
  const re = /\b(?:Remove-Item|Remove-ItemProperty|Remove|rmdir|rm|del|erase|unlink|shred|mv|Move-Item|Clear-format|Clear-Disk)\b([^;\r\n]{0,240})/g;
  for (const m of text.matchAll(re)) {
    const seg = m[1] || "";
    for (const p of seg.matchAll(PATH_WIN)) found.push(p[0]);
    for (const p of seg.matchAll(PATH_UNIX)) found.push(p[0]);
    for (const lit of seg.matchAll(/(["'])([^"'\n]{1,})\1/g)) {
      // 引号里可能是散文，不是路径
      if (looksPathish(lit[2])) found.push(lit[2]);
    }
    for (const b of seg.matchAll(BARE_ROOT)) found.push(b[1]);
    // 盘根写法：动词片段里出现 X:\ 而后面什么都没有（或只到引号/结尾）
    for (const p of seg.matchAll(PATH_WIN_ROOT)) {
      const at = p.index;
      const tail = seg.slice(at + 3).trim();
      if (!tail || /^["']/.test(tail)) found.push(seg.slice(at, at + 3));
    }
    // 变量形式的路径（$w\$f、$_.FullName）也要成主体，好让规则层知道「这里删的是个说不清的东西」
    for (const v of seg.matchAll(/\$[A-Za-z_][A-Za-z0-9_]*(?:[\\/]\$?[A-Za-z_][A-Za-z0-9_]*)+/g)) found.push(v[0]);
    for (const v of seg.matchAll(/\$env:[A-Za-z_][A-Za-z0-9_]*(?:[\\/][^\s"'()|;,]*)?/g)) found.push(v[0]);
  }
  return [...new Set(found.filter((v) => looksPathish(v) && !isDeviceSink(v)))];
}

// 根形态判定走路径语义，不挤进 mega-regex（那条到 60 字符已是坏味道，且实测漏判）。
const HOME = String(process.env.USERPROFILE || process.env.HOME || "").toLowerCase().replace(/[\\/]+$/, "");

const SYS_ROOTS = ["etc", "usr", "var", "windows", "winnt", "program files", "programfiles", "users", "home", "root", "proc", "sys", "srv", "mnt", "boot"];
// 这些根之下不存在「工作区内的深层安全目录」，故整棵树按根形态判
const SYS_TREE = ["dev", "proc", "sys", "boot", "sbin", "bin", "lib", "system32", "windows"];

export function isRootish(value) {
  const raw = String(value == null ? "" : value).trim().replace(/^["']+|["']+$/g, "").replace(/\s+/g, "");
  if (!raw) return false;
  const s = raw.toLowerCase();
  // 重定向设备结点是【丢弃输出】的目标，不是删除目标：`2>/dev/null` 在真实命令里极常见，
  // 而 /dev 落在 SYS_TREE ⇒ 旧实现把每条带 2>/dev/null 的递归删除都判成根形态（回放里 31 条）。
  // destroyTargets 早已排除设备结点，isRootish 这条路径漏了。
  if (isDeviceSink(s)) return false;
  if (/^[a-z]:[\\/]?$/.test(s)) return true;                        // C:  C:\  C:/
  if (s === "/" || s === "//" || s === "~" || s === "~/" || s === "*" || s === "./") return true;
  if (s === "$home" || s === "%userprofile%" || s === "$env:userprofile") return true;
  let segs = s.split(/[\\/]+/).filter(Boolean);
  if (!segs.length) return true;                                    // 只剩分隔符 ⇒ 根
  if (HOME) {
    const homeSegs = HOME.split(/[\\/]+/);
    if (homeSegs.every((seg, i) => segs[i] === seg)) segs = segs.slice(homeSegs.length);
  }
  if (segs[0] === "~" || segs[0] === "$home" || segs[0] === "%userprofile%") segs = segs.slice(1);
  if (segs.length === 0) return true;                                // 家目录本身
  const drive = /^[a-z]:$/.test(segs[0]);
  if (drive) segs = segs.slice(1);
  if (segs.length === 0) return true;                                // 盘根
  if (segs.length === 1 && SYS_ROOTS.includes(segs[0])) return true;  // C:\Windows, /etc
  if (!drive && SYS_TREE.includes(segs[0])) return true;              // /dev/sda, /etc/passwd：系统根树下任意深度
  if (drive && segs[0] === "users" && segs.length === 2) return true;      // C:\Users\<name>：家目录，与 /home/<name> 同构（不能依赖 USERPROFILE 有没有设）
  if (!drive && segs[0] === "home" && segs.length === 2) return true; // /home/<name>
  return false;
}

export function isCredentialish(value) {
  return CRED_RE.test(String(value));
}

// 规则层用这个取代 CRED_RE 全文匹配（旧的会把 URL 路径里的 token 一词当成凭据）
export function credentialishSubject(s) {
  if (!s) return false;
  return isCredentialish2(s.kind, s.value);
}
