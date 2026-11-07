// 审批通道缺失时的降级逻辑（2026-11-07 活宿主源码 + 实测核对）。
//
// 宿主 dsh-tools/lib/pipeline.js 的 serviceAsk 有三种退化：
//   · approval 服务【不存在】      → reason = ask.reason ?? 通用文案  ⇒ 【我的理由保留】
//   · exec.agent 不存在           → reason = 通用文案（无 agent 可路由） ⇒ 【理由被吃掉】
//   · outcome === "unavailable"   → reason = 通用文案（有服务、无通道）   ⇒ 【理由被吃掉】
// 本机实测走第三种：闸门回了详细理由，模型只看到
//   Error: tool "pwsh" requires approval, but no approval channel is available
// ⇒ 拦得住，但【为什么拦】丢了。post-execute 也救不了：denial 直接走 post-result 分派，
//    那条路径不跑 postExecute（源码里 case "post-result": break）。
// 所以只能【学会】这件事：撞到一次就记住，之后同一会话里把 ask/review 直接发成 deny，
// 用我们自己的 reason 字段 —— 文案走 denialReason 那条正规通道，保证不丢解释。
//
// 代价说清楚：降级后就再也不会真的「问人」了，即便通道后来出现。
// 判据是保守的：只在【本次确实是闸门提出的 ask】且【失败文案是审批类通用文案】时才降级。
export function isApprovalUnavailableText(text) {
  const t = String(text || "");
  return /requires approval/.test(t) &&
    (/no approval channel is available/.test(t) || /no agent to route it through/.test(t));
}
export function askKindFor(verdict, noChannel) {
  if (verdict !== "ask" && verdict !== "review") return null;
  return noChannel ? "deny" : "ask";
}
