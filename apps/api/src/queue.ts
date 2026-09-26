import { Queue } from "bullmq";
import IORedis from "ioredis";
import { config } from "./config";

const redisOptions = { maxRetriesPerRequest: null } as const;
export const mediaRedis = new IORedis(config.REDIS_URL, redisOptions);
export const outboxRedis = new IORedis(config.REDIS_URL, redisOptions);
export const complianceRedis = new IORedis(config.REDIS_URL, redisOptions);
mediaRedis.on("error", (error) => console.error({ error }, "media Redis connection error"));
outboxRedis.on("error", (error) => console.error({ error }, "outbox Redis connection error"));
complianceRedis.on("error", (error) => console.error({ error }, "compliance Redis connection error"));

export const mediaQueue = new Queue("media", { connection: mediaRedis });
export const outboxQueue = new Queue("outbox", { connection: outboxRedis });
export const complianceQueue = new Queue("compliance", { connection: complianceRedis });

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_resolve, reject) => {
      setTimeout(() => reject(new Error(`Redis queue operation timed out after ${timeoutMs}ms`)), timeoutMs).unref();
    })
  ]);
}

export async function enqueueMediaProcessing(mediaId: string, jobId: string): Promise<void> {
  await withTimeout(
    mediaQueue.add("process", { mediaId }, {
      jobId,
      removeOnComplete: 1000,
      removeOnFail: 1000
    }),
    3_000
  );
}

export async function enqueueOutbox(eventId: string): Promise<void> {
  try {
    await withTimeout(
      outboxQueue.add("dispatch", { eventId }, { removeOnComplete: 1000, removeOnFail: 1000 }),
      3_000
    );
  } catch (error) {
    // The database outbox remains the source of truth. A worker maintenance tick retries pending rows.
    console.error({ eventId, error }, "failed to enqueue outbox event");
  }
}

export async function enqueueExportBuild(exportId: string): Promise<void> {
  try {
    await withTimeout(
      complianceQueue.add("build_export", { exportId }, {
        jobId: `compliance-export-${exportId}`,
        attempts: 5,
        backoff: { type: "exponential", delay: 10_000 },
        removeOnComplete: 1000,
        removeOnFail: 1000
      }),
      3_000
    );
  } catch (error) {
    // 数据库中的 pending 行是事实来源，worker 维护 tick 会兜底重试。
    console.error({ exportId, error }, "failed to enqueue compliance export job");
  }
}

export async function closeQueues(): Promise<void> {
  await Promise.all([mediaQueue.close(), outboxQueue.close(), complianceQueue.close()]);
  if (mediaRedis.status !== "end") mediaRedis.disconnect();
  if (outboxRedis.status !== "end") outboxRedis.disconnect();
  if (complianceRedis.status !== "end") complianceRedis.disconnect();
}
