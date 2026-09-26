<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { apiFetch } from "../lib/api";

type Verification = {
  object_kind: string;
  location: string;
  bucket: string | null;
  object_key: string | null;
  expected_sha256: string | null;
  verified: boolean;
  check_method: string;
  detail: Record<string, unknown>;
  checked_at: string;
};

type Certificate = {
  certificateType: string;
  deletionRequestId: string;
  status: string;
  scheduledPurgeAfter: string;
  completedAt: string;
  beforeState: Record<string, unknown>;
  purgeEvidence: {
    evidenceDigest?: string;
    objectCount?: number;
    allObjectsVerifiedAbsent?: boolean;
    databaseResidue?: Record<string, string>;
  };
  verifications: Verification[];
};

const route = useRoute();
const certificate = ref<Certificate | null>(null);
const error = ref("");

onMounted(async () => {
  try {
    certificate.value = await apiFetch<Certificate>(
      `/me/compliance/deletion-requests/${String(route.params.id)}/certificate`
    );
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "无法加载删除证明";
  }
});
</script>

<template>
  <section style="max-width: 900px; margin: 30px auto">
    <h1>数据删除证明</h1>
    <p v-if="error" class="error-box">{{ error }}</p>
    <article v-if="certificate" class="card">
      <div class="card-body">
        <p class="muted">证明类型：{{ certificate.certificateType }}</p>
        <dl class="cert-grid">
          <dt>删除请求</dt><dd>{{ certificate.deletionRequestId }}</dd>
          <dt>计划清除时间</dt><dd>{{ new Date(certificate.scheduledPurgeAfter).toLocaleString() }}</dd>
          <dt>实际完成时间</dt><dd>{{ new Date(certificate.completedAt).toLocaleString() }}</dd>
          <dt>对象删除验证</dt>
          <dd>{{ certificate.purgeEvidence.allObjectsVerifiedAbsent ? "全部验证为不存在" : "存在未验证项" }}</dd>
          <dt>证据摘要</dt><dd><code>{{ certificate.purgeEvidence.evidenceDigest ?? "—" }}</code></dd>
        </dl>

        <h2>逐项验证</h2>
        <table class="cert-table">
          <thead>
            <tr><th>时间</th><th>类型</th><th>位置</th><th>方法</th><th>结果</th></tr>
          </thead>
          <tbody>
            <tr v-for="(item, index) in certificate.verifications" :key="index">
              <td>{{ new Date(item.checked_at).toLocaleString() }}</td>
              <td>{{ item.object_kind }}</td>
              <td class="mono">{{ item.location }}</td>
              <td>{{ item.check_method }}</td>
              <td :class="item.verified ? 'ok' : 'bad'">{{ item.verified ? "✓ 不存在" : "✗ 仍存在" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>
  </section>
</template>

<style scoped>
.cert-grid {
  display: grid;
  grid-template-columns: 160px 1fr;
  gap: 6px 14px;
}
.cert-grid dt {
  font-weight: 600;
  color: #555;
}
.cert-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 12px;
  font-size: 0.88rem;
}
.cert-table th,
.cert-table td {
  border-bottom: 1px solid var(--border-color, #e5e7eb);
  padding: 7px 9px;
  text-align: left;
}
.mono {
  font-family: ui-monospace, monospace;
  word-break: break-all;
}
.ok {
  color: #15803d;
  font-weight: 600;
}
.bad {
  color: #b91c1c;
  font-weight: 600;
}
</style>
