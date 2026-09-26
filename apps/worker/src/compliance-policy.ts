// 纯函数决策层：不接触数据库/对象存储，便于单测覆盖保留期与法务保留语义。

export type DeletionDecisionInput = {
  requestStatus: "scheduled" | "held" | "processing" | "completed" | "cancelled";
  now: Date;
  purgeAfter: Date;
  activeHoldCount: number;
};

export type DeletionDecision = {
  action: "purge" | "hold" | "wait";
  reason: string;
};

export function decideDeletion(input: DeletionDecisionInput): DeletionDecision {
  if (input.requestStatus === "cancelled" || input.requestStatus === "completed" || input.requestStatus === "processing") {
    return { action: "wait", reason: `request_${input.requestStatus}` };
  }
  if (input.now.getTime() < input.purgeAfter.getTime()) {
    // 保留期内（到期时刻之前）不得提前清除。
    return { action: "wait", reason: "within_retention_window" };
  }
  if (input.activeHoldCount > 0) {
    return { action: "hold", reason: "active_legal_hold" };
  }
  return { action: "purge", reason: "due" };
}
