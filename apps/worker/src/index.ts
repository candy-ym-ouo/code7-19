import { Queue, Worker } from "bullmq";
import IORedis from "ioredis";
import { config } from "./config";
import { pool } from "./db";
import { processMediaJob, cleanupOriginalMedia, cleanupDeletedMediaObjects, markStaleFeatures, recoverStuckMedia, markUnreferencedMediaDeleted } from "./media-job";
import { dispatchOutbox, recoverStuckOutbox } from "./outbox";
import {
  processExportJob,
  processDueDeletionRequests,
  reevaluateHeldDeletions,
  recoverStuckDeletions,
  recoverStuckExports,
  sweepExpiredExports
} from "./compliance-job";

const redisOptions = { maxRetriesPerRequest: null } as const;
const queueConnection = new IORedis(config.REDIS_URL, redisOptions);
const mediaWorkerConnection = new IORedis(config.REDIS_URL, redisOptions);
const outboxWorkerConnection = new IORedis(config.REDIS_URL, redisOptions);
const complianceWorkerConnection = new IORedis(config.REDIS_URL, redisOptions);

for (const [name, connection] of [
  ["queue", queueConnection],
  ["media worker", mediaWorkerConnection],
  ["outbox worker", outboxWorkerConnection],
  ["compliance worker", complianceWorkerConnection]
] as const) {
  connection.on("error", (error) => console.error({ error, connection: name }, "Redis connection error"));
}
const mediaQueue = new Queue("media", { connection: queueConnection });
const complianceQueue = new Queue("compliance", { connection: queueConnection });

const mediaWorker = new Worker("media", async (job) => {
  if (job.name !== "process") return;
  await processMediaJob(String(job.data.mediaId));
}, { connection: mediaWorkerConnection, concurrency: 2 });

const outboxWorker = new Worker("outbox", async (job) => {
  if (job.name !== "dispatch") return;
  await dispatchOutbox(job.data?.eventId ? String(job.data.eventId) : undefined);
}, { connection: outboxWorkerConnection, concurrency: 2 });

const complianceWorker = new Worker("compliance", async (job) => {
  if (job.name !== "build_export") return;
  await processExportJob(String(job.data.exportId));
}, { connection: complianceWorkerConnection, concurrency: 1 });

mediaWorker.on("failed", (job, error) => console.error({ jobId: job?.id, error }, "media job failed"));
outboxWorker.on("failed", (job, error) => console.error({ jobId: job?.id, error }, "outbox job failed"));
complianceWorker.on("failed", (job, error) => console.error({ jobId: job?.id, error }, "compliance job failed"));

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_resolve, reject) => {
      setTimeout(() => reject(new Error(`Redis queue operation timed out after ${timeoutMs}ms`)), timeoutMs).unref();
    })
  ]);
}

let maintenanceRunning = false;

async function maintenanceTick() {
  if (maintenanceRunning) return;
  maintenanceRunning = true;
  try {
    await recoverStuckOutbox();
    await dispatchOutbox();
    const stuckMedia = await recoverStuckMedia();
    for (const mediaId of stuckMedia) {
      await withTimeout(mediaQueue.add("process", { mediaId }, {
        jobId: `media-recover-${mediaId}-${Date.now()}`,
        removeOnComplete: 1000,
        removeOnFail: 1000
      }), 3_000);
    }
    await cleanupOriginalMedia();
    await markUnreferencedMediaDeleted();
    await cleanupDeletedMediaObjects();
    await markStaleFeatures();

    // 合规编排：恢复卡住的导出 → 兜底补队 → 到期导出清除 → 法务保留复议 → 到期删除。
    const stuckExports = await recoverStuckExports();
    for (const exportId of stuckExports) {
      await withTimeout(complianceQueue.add("build_export", { exportId }, {
        jobId: `compliance-recover-${exportId}-${Date.now()}`,
        removeOnComplete: 1000,
        removeOnFail: 1000
      }), 3_000);
    }
    // Redis 通知丢失时，pending 超过 2 分钟的导出也兜底入队。
    const pendingExports = await pool.query<{ id: string }>(
      `SELECT id FROM compliance_exports
       WHERE status = 'pending' AND created_at < now() - interval '2 minutes'
       LIMIT 10`
    );
    for (const row of pendingExports.rows) {
      await withTimeout(complianceQueue.add("build_export", { exportId: row.id }, {
        jobId: `compliance-pending-${row.id}`,
        removeOnComplete: 1000,
        removeOnFail: 1000
      }), 3_000).catch(() => undefined);
    }
    await sweepExpiredExports();
    await recoverStuckDeletions();
    await reevaluateHeldDeletions();
    await processDueDeletionRequests();
  } catch (error) {
    console.error({ error }, "maintenance tick failed");
  } finally {
    maintenanceRunning = false;
  }
}

await maintenanceTick();
const maintenanceTimer = setInterval(() => void maintenanceTick(), 60_000);
maintenanceTimer.unref();

async function shutdown(signal: string) {
  console.log(`worker shutting down: ${signal}`);
  clearInterval(maintenanceTimer);
  await Promise.all([mediaWorker.close(), outboxWorker.close(), complianceWorker.close(), mediaQueue.close(), complianceQueue.close()]);
  for (const connection of [queueConnection, mediaWorkerConnection, outboxWorkerConnection, complianceWorkerConnection]) {
    if (connection.status !== "end") connection.disconnect();
  }
  await pool.end();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
