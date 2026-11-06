// 只追加账本。一行一裁决。绝不原地改写，绝不记参数全文（避免把凭据抄进账本）。
import fs from "node:fs";
import path from "node:path";

// 入账脱敏（设计 §5：绝不记参数全文）。两类真泄漏面：
//   URL 的 query 是最常见的凭据载体 ⇒ 只留 协议 主机 路径
//   op-* 主体的值是命令全文头 ⇒ 只留 kind
// env 主体记的是变量【名】不是值，审计需要它，保留。
function scrub(v) {
  if (typeof v === "string") {
    // URL 带 query ⇒ 砍掉 query 只留 协议/主机/路径；query 是最常见的凭据载体
    if (v.includes("://") && v.includes("?")) return v.split("?")[0] + "?<query-scrubbed>";
    return v;
  }
  if (Array.isArray(v)) return v.map(scrub);
  if (v && typeof v === "object") {
    const out = {};
    for (const [k, x] of Object.entries(v)) {
      // op-* 主体的 value 是命令全文头 ⇒ 不入账
      if (k === "value" && typeof v.kind === "string" && v.kind.startsWith("op-")) continue;
      out[k] = scrub(x);
    }
    return out;
  }
  return v;
}

const CAP = Number(process.env.ACTION_GATE_LEDGER_CAP || 512 * 1024);
const KEEP = Number(process.env.ACTION_GATE_KEEP_ARCHIVES || 3);

export function makeLedger(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let seq = 0;
  return {
    file,
    append(rec) {
      rotateIfNeeded(file);
      const line = JSON.stringify(scrub({ ts: new Date().toISOString(), seq: seq++, ...rec }));
      fs.appendFileSync(file, line + "\n", "utf8");
      return line;
    },
    readAll() {
      if (!fs.existsSync(file)) return [];
      return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => {
        try { return JSON.parse(l); } catch { return null; }
      }).filter(Boolean);
    },
  };
}

// 先写后轮转的反面：轮转只在新一次写入【之前】按体量决定，且必须先把当前文件搬走。
// 顺序错了会把未读的告警整份搬进归档＝漏报。这里保持「容量够就不动，超了才归档」。
function rotateIfNeeded(file) {
  let st;
  try { st = fs.statSync(file); } catch { return; }
  if (!st.isFile() || st.size < CAP) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const arc = file + "." + stamp + ".archived";
  fs.renameSync(file, arc);
  const dir = path.dirname(file);
  const arcs = fs.readdirSync(dir).filter((f) => f.startsWith(path.basename(file) + ".") && f.endsWith(".archived")).sort();
  while (arcs.length > KEEP) {
    const old = arcs.shift();
    fs.rmSync(path.join(dir, old), { force: true });
  }
}
