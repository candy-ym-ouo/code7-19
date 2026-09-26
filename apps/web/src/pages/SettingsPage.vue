<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { apiFetch } from "../lib/api";
import { useAuthStore } from "../stores/auth";

type ComplianceExport = {
  id: string;
  status: "pending" | "processing" | "ready" | "failed" | "expired";
  byteSize: number | null;
  fileCount: number | null;
  sha256: string | null;
  failureCode: string | null;
  expiresAt: string;
  completedAt: string | null;
  createdAt: string;
};

type DeletionRequest = {
  id: string;
  status: "scheduled" | "held" | "processing" | "completed" | "cancelled";
  purge_after: string;
  held_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  created_at: string;
};

const auth = useAuthStore();
const router = useRouter();
const error = ref("");
const notice = ref("");
const exports_ = ref<ComplianceExport[]>([]);
const deletionRequests = ref<DeletionRequest[]>([]);
const loading = ref(false);

const statusLabel: Record<ComplianceExport["status"], string> = {
  pending: "排队中",
  processing: "正在生成",
  ready: "可下载",
  failed: "生成失败",
  expired: "已到期删除"
};

async function refreshState() {
  try {
    const [exportList, deletionList] = await Promise.all([
      apiFetch<ComplianceExport[]>("/me/compliance/exports"),
      apiFetch<DeletionRequest[]>("/me/compliance/deletion-requests")
    ]);
    exports_.value = exportList;
    deletionRequests.value = deletionList;
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "加载合规状态失败";
  }
}

onMounted(refreshState);

async function requestExport() {
  error.value = "";
  notice.value = "";
  setLoading(true, "正在创建导出任务…");
  try {
    await apiFetch("/me/compliance/exports", { method: "POST" });
    notice.value = "导出任务已提交，生成完成后可在此下载（保留 30 天，到期自动删除）。";
    setTimeout(() => void refreshState(), 1500);
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "导出失败";
  } finally {
    loading.value = false;
  }
}

async function downloadExport(id: string) {
  error.value = "";
  try {
    const { downloadUrl } = await apiFetch<{ downloadUrl: string }>(
      `/me/compliance/exports/${id}/download`,
      { method: "POST" }
    );
    window.location.assign(downloadUrl);
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "获取下载链接失败";
  }
}

async function deleteAccount() {
  const confirmation = window.prompt("此操作不可撤销。输入 DELETE 确认进入 30 天删除冷静期，冷静期内可撤销。");
  if (confirmation !== "DELETE") return;
  try {
    await apiFetch("/me/compliance/deletion-requests", { method: "POST", body: {} });
    await auth.logout();
    await router.push("/map");
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "删除申请失败";
  }
}

async function cancelDeletion(id: string) {
  try {
    await apiFetch(`/me/compliance/deletion-requests/${id}/cancel`, { method: "POST" });
    notice.value = "删除申请已撤销，账号恢复正常。";
    await refreshState();
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "撤销失败";
  }
}

function setLoading(value: boolean, message: string) {
  loading.value = value;
  if (value) notice.value = message;
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}
</script>

<template>
  <section style="max-width: 860px; margin: 30px auto">
    <div class="page-heading">
      <div>
        <h1>账号设置 · 数据合规</h1>
        <p>统一管理数据导出（可携带归档）、法务保留状态和到期删除。保留期内不会提前清除，到期删除留存可验证证明。</p>
      </div>
    </div>
    <p v-if="error" class="error-box">{{ error }}</p>
    <p v-if="notice" class="success-box">{{ notice }}</p>
    <div class="stack">
      <section class="card">
        <div class="card-body">
          <h2>数据导出</h2>
          <p class="muted">
            异步生成包含账号资料、投稿、评论、时效确认、举报和隐私处理后图片的 tar 归档；
            内含 MANIFEST.json 清单与每个文件的 SHA-256，可校验完整性。原始图片不会导出。
          </p>
          <button class="button secondary" type="button" :disabled="loading" @click="requestExport">申请导出</button>
          <table v-if="exports_.length" class="compliance-table">
            <thead>
              <tr><th>创建时间</th><th>状态</th><th>文件数</th><th>到期时间</th><th>操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="item in exports_" :key="item.id">
                <td>{{ formatDate(item.createdAt) }}</td>
                <td>{{ statusLabel[item.status] }}</td>
                <td>{{ item.fileCount ?? "—" }}</td>
                <td>{{ formatDate(item.expiresAt) }}</td>
                <td>
                  <button v-if="item.status === 'ready'" class="button secondary small" type="button" @click="downloadExport(item.id)">
                    下载（10 分钟链接）
                  </button>
                  <span v-else-if="item.status === 'failed'" class="muted">失败：{{ item.failureCode }}</span>
                  <span v-else-if="item.status === 'expired'" class="muted">归档已删除</span>
                  <span v-else class="muted">准备中…</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card">
        <div class="card-body">
          <h2>删除账号</h2>
          <p class="muted">
            申请后进入 30 天冷静期（保留期内任何任务都不会提前清除）。到期后若无法务保留，
            系统删除全部媒体对象与可识别身份信息，并逐项验证“对象/记录已不存在”后留存删除证明。
          </p>
          <div v-for="item in deletionRequests" :key="item.id" class="deletion-row">
            <template v-if="item.status === 'scheduled' || item.status === 'held'">
              <strong>{{ item.status === "held" ? "已被法务保留挂起" : "计划清除时间" }}：</strong>
              {{ formatDate(item.purge_after) }}
              <button class="button secondary small" type="button" @click="cancelDeletion(item.id)">撤销删除申请</button>
            </template>
            <template v-else-if="item.status === 'processing'">
              <strong>删除正在执行，无法撤销。</strong>
            </template>
            <template v-else-if="item.status === 'completed'">
              <span>账号已于 {{ formatDate(item.completed_at) }} 完成删除并出具证明。</span>
              <router-link class="button secondary small" :to="`/compliance/deletion/${item.id}`">查看删除证明</router-link>
            </template>
            <template v-else>
              <span class="muted">删除申请已于 {{ formatDate(item.cancelled_at) }} 撤销。</span>
            </template>
          </div>
          <button class="button danger" type="button" @click="deleteAccount">申请删除账号</button>
        </div>
      </section>
    </div>
  </section>
</template>

<style scoped>
.compliance-table {
  width: 100%;
  margin-top: 16px;
  border-collapse: collapse;
  font-size: 0.92rem;
}
.compliance-table th,
.compliance-table td {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border-color, #e5e7eb);
}
.button.small {
  padding: 4px 10px;
  font-size: 0.85rem;
}
.deletion-row {
  display: flex;
  gap: 12px;
  align-items: center;
  margin: 10px 0;
  flex-wrap: wrap;
}
</style>
