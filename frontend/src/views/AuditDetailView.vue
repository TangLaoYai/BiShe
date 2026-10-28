<template>
  <div v-loading="loading">
    <el-card shadow="never" style="margin-bottom:15px">
      <template #header>
        <div class="card-header">
          <span>审计概览</span>
          <div class="actions">
            <el-button type="primary" plain @click="downloadReport" :disabled="!detail.audit_id">
              导出 TXT 报告
            </el-button>
            <el-button type="primary" @click="downloadPdf" :disabled="!detail.audit_id">
              导出 PDF 报告
            </el-button>
            <el-button type="success" :disabled="!canChain" @click="chainEvidence">
              {{ detail.evidence ? '已上链存证' : '上链存证' }}
            </el-button>
            <el-button type="warning" plain :disabled="!detail.evidence" @click="verifyEvidence">
              存证校验
            </el-button>
          </div>
        </div>
      </template>

      <!-- 实时进度条：running 状态可见，SSE 推送自动更新 -->
      <div v-if="progress.status === 'running'" class="progress-box">
        <div class="progress-label">
          <span class="spin-loader"></span>
          <b>检测进行中…</b>
          <span class="progress-current">{{ progress.current ? '当前：' + progress.current : '初始化中' }}</span>
          <span class="progress-vulns">已检漏洞 {{ progress.vulns }}</span>
        </div>
        <el-progress :percentage="progress.percent" :stroke-width="14"
                     :status="progress.percent === 100 ? 'success' : ''" />
        <div class="progress-step">
          步骤 {{ progress.done }} / {{ progress.total }}
        </div>
      </div>

      <el-descriptions v-if="!progress.status || progress.status !== 'running'" :column="3" border>
        <el-descriptions-item label="审计编号">{{ detail.audit_id }}</el-descriptions-item>
        <el-descriptions-item label="合约名称">{{ detail.contract?.contract_name }}</el-descriptions-item>
        <el-descriptions-item label="审计时间">{{ detail.audit_time }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="statusType(detail.status)" size="small">{{ detail.status || '-' }}</el-tag>
          <el-tag v-if="detail.status === 'running'" type="warning" size="small" style="margin-left:8px">
            检测进行中…
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="上传时间">{{ detail.contract?.upload_time }}</el-descriptions-item>
        <el-descriptions-item label="漏洞统计">
          <el-tag type="danger" size="small" style="margin-right:6px">高危 {{ detail.counts?.['高危'] || 0 }}</el-tag>
          <el-tag type="warning" size="small" style="margin-right:6px">中危 {{ detail.counts?.['中危'] || 0 }}</el-tag>
          <el-tag type="info" size="small">低危 {{ detail.counts?.['低危'] || 0 }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <el-alert v-if="detail.evidence" type="success" :closable="false" style="margin-top:12px">
        <p>已上链存证　交易哈希：<span class="tx-hash">{{ detail.evidence.tx_hash }}</span>
          <el-button link type="primary" size="small" @click="copyTx(detail.evidence.tx_hash)">复制</el-button>
          　上链时间：{{ detail.evidence.chain_time }}</p>
      </el-alert>
    </el-card>

    <el-card shadow="never">
      <template #header><span>漏洞详情（{{ detail.vulns?.total || 0 }}）</span></template>
      <el-table :data="detail.vulns?.items || []" stripe @row-click="showVuln" style="cursor:pointer">
        <el-table-column type="index" label="#" width="50"
                         :index="(i) => (detail.vulns?.page - 1) * detail.vulns?.page_size + i + 1" />
        <el-table-column prop="vul_type" label="漏洞类型" min-width="170" />
        <el-table-column label="风险等级" width="100">
          <template #default="{ row }">
            <el-tag :type="levelType(row.risk_level)" size="small">{{ row.risk_level }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="置信度" width="90">
          <template #default="{ row }">
            <el-tag :type="confidenceType(row.confidence)" size="small" effect="plain">
              {{ row.confidence || '中' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="location" label="漏洞位置" min-width="210" show-overflow-tooltip />
        <el-table-column prop="description" label="漏洞描述" min-width="260" show-overflow-tooltip />
        <el-table-column prop="suggestion" label="修复建议" min-width="240" show-overflow-tooltip />
      </el-table>
      <el-empty v-if="detail.status === '完成' && !detail.vulns?.total" description="本次审计未发现漏洞" />
      <div v-if="detail.vulns?.total > detail.vulns?.page_size"
           style="margin-top:12px; text-align:right">
        <el-pagination background layout="prev, pager, next, total"
                       :total="detail.vulns?.total || 0"
                       :page-size="detail.vulns?.page_size || 20"
                       :current-page="detail.vulns?.page || 1"
                       @current-change="onVulnPageChange" />
      </div>
    </el-card>

    <el-dialog v-model="vulnVisible" :title="currentVuln.vul_type" width="700px">
      <el-descriptions :column="1" border>
        <el-descriptions-item label="风险等级">
          <el-tag :type="levelType(currentVuln.risk_level)" size="small">{{ currentVuln.risk_level }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="检测置信度">
          <el-tag :type="confidenceType(currentVuln.confidence)" size="small" effect="plain">
            {{ currentVuln.confidence || '中' }}
          </el-tag>
          <span class="confidence-hint">
            {{ confidenceHint(currentVuln.confidence) }}
          </span>
        </el-descriptions-item>
        <el-descriptions-item label="漏洞位置">{{ currentVuln.location }}</el-descriptions-item>
        <el-descriptions-item label="漏洞描述">{{ currentVuln.description }}</el-descriptions-item>
        <el-descriptions-item label="修复建议">{{ currentVuln.suggestion }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <el-dialog v-model="verifyVisible" title="存证校验结果" width="760px">
      <el-result v-if="verifyResult" :icon="verifyResult.consistent ? 'success' : 'error'"
                 :title="verifyResult.consistent ? '校验一致：本地数据未被篡改' : '校验不一致：本地数据可能已被篡改！'">
        <template #sub-title>
          <div style="text-align:left; font-size:13px">
            <p>合约源码哈希对比：{{ verifyResult.contract_match ? '一致' : '不一致' }}</p>
            <p class="tx-hash">本地：{{ verifyResult.local?.contract_hash }}</p>
            <p class="tx-hash">链上：{{ verifyResult.chain?.contract_hash }}</p>
            <p style="margin-top:8px">审计记录哈希对比：{{ verifyResult.audit_match ? '一致' : '不一致' }}</p>
            <p class="tx-hash">本地：{{ verifyResult.local?.audit_hash }}</p>
            <p class="tx-hash">链上：{{ verifyResult.chain?.audit_hash }}</p>
          </div>
        </template>
      </el-result>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const route = useRoute()
const auditId = route.params.auditId
const detail = reactive({})
const loading = ref(false)
const vulnVisible = ref(false)
const currentVuln = reactive({})
const verifyVisible = ref(false)
const verifyResult = ref(null)

// SSE 实时进度状态
const progress = reactive({ status: '', total: 0, done: 0, percent: 0, current: '', vulns: 0 })
let evtSource = null
let fallbackTimer = null

const canChain = computed(() => detail.status === '完成' && !detail.evidence)
const statusType = (s) => s === '完成' ? 'success' : s === '失败' ? 'danger' : 'warning'
const levelType = (l) => l === '高危' ? 'danger' : l === '中危' ? 'warning' : 'info'
const confidenceType = (c) => c === '高' ? 'success' : c === '中' ? 'warning' : 'info'
const confidenceHint = (c) => c === '高'
  ? '规则可确定命中，误报概率低'
  : c === '低'
    ? '弱信号提示，仅供参考'
    : '启发式推断，建议人工复核上下文'

async function loadDetail(vulnPage = 1) {
  try {
    const data = await api.get(`/audits/${auditId}`, {
      params: { vuln_page: vulnPage, vuln_page_size: 20 }
    })
    Object.assign(detail, data)
    if (data.status === 'running') {
      ensureSSE()
    } else if (evtSource) {
      evtSource.close()
      evtSource = null
    }
  } catch (e) {
    ElMessage.error(e.message)
  }
}

// ===== SSE 实时进度 =====
function ensureSSE() {
  if (evtSource) return
  // EventSource 自动带 cookie（credentials 同域默认）
  evtSource = new EventSource(`/api/audits/${auditId}/sse`)
  evtSource.addEventListener('progress', (ev) => {
    const p = JSON.parse(ev.data)
    Object.assign(progress, p)
    if (progress.percent >= 90 && !fallbackTimer) {
      // SSE 可能在 done 前断开，兜底拉一下详情
      fallbackTimer = setTimeout(() => loadDetail(detail.vulns?.page || 1), 3000)
    }
  })
  evtSource.addEventListener('done', (ev) => {
    const d = JSON.parse(ev.data)
    ElMessage.success(`审计${d.status || '完成'}：检出漏洞 ${d.vuln_count || 0} 条`)
    if (evtSource) { evtSource.close(); evtSource = null }
    Object.assign(progress, { status: d.status || '完成', percent: 100 })
    setTimeout(() => loadDetail(detail.vulns?.page || 1), 300)
  })
  evtSource.addEventListener('timeout', () => {
    ElMessage.warning('审计进度推送超时，切换轮询降级')
    if (evtSource) { evtSource.close(); evtSource = null }
    fallbackTimer = setInterval(() => loadDetail(detail.vulns?.page || 1), 2000)
  })
  evtSource.onerror = () => {
    // 静默：可能后端还没准备好，等一轮重试
  }
}

function onVulnPageChange(p) {
  loadDetail(p)
}

function showVuln(row) {
  Object.assign(currentVuln, row)
  vulnVisible.value = true
}

async function downloadReport() {
  try {
    const resp = await fetch(`/api/audits/${auditId}/report`, { credentials: 'include' })
    if (!resp.ok) throw new Error('报告下载失败')
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${auditId}_审计报告.txt`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function downloadPdf() {
  try {
    const resp = await fetch(`/api/audits/${auditId}/report.pdf`, { credentials: 'include' })
    if (!resp.ok) throw new Error('PDF 报告下载失败')
    const blob = await resp.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${auditId}_审计报告.pdf`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function chainEvidence() {
  try {
    await ElMessageBox.confirm(
      '将把合约源码哈希与审计记录哈希写入 FISCO BCOS 区块链存证，操作不可撤销，确定上链吗？',
      '上链存证', { type: 'warning', confirmButtonText: '确认上链' })
    const data = await api.post('/evidence', { audit_id: auditId })
    await ElMessageBox.alert(
      `<p>上链存证成功！</p><p>交易哈希：<span class="tx-hash">${data.tx_hash}</span></p><p>上链时间：${data.chain_time}</p>`,
      '存证成功', { dangerouslyUseHTMLString: true, confirmButtonText: '知道了' })
    loadDetail()
  } catch (e) {
    if (e !== 'cancel' && e?.message) ElMessage.error(e.message)
  }
}

async function verifyEvidence() {
  try {
    const data = await api.post('/evidence/verify', { audit_id: auditId })
    verifyResult.value = data
    verifyVisible.value = true
  } catch (e) {
    ElMessage.error(e.message)
  }
}

function copyTx(hash) {
  navigator.clipboard.writeText(hash)
  ElMessage.success('交易哈希已复制')
}

onMounted(loadDetail)
onBeforeUnmount(() => {
  if (evtSource) { evtSource.close(); evtSource = null }
  if (fallbackTimer) { clearInterval(fallbackTimer); clearTimeout(fallbackTimer); fallbackTimer = null }
})
</script>

<style scoped>
.card-header { display: flex; justify-content: space-between; align-items: center; }
.confidence-hint { margin-left: 8px; font-size: 12px; color: #909399; }
.tx-hash { font-family: Consolas, Menlo, monospace; font-size: 12px; color: #409EFF; word-break: break-all; }
.progress-box { margin-bottom: 16px; padding: 14px 18px; background: linear-gradient(135deg, #fdf6ec 0%, #f0f9ff 100%); border: 1px dashed #94a3b8; border-radius: 8px; }
.progress-label { display: flex; align-items: center; gap: 14px; font-size: 13px; color: #303133; margin-bottom: 10px; flex-wrap: wrap; }
.progress-current { color: #409EFF; font-family: Consolas, monospace; }
.progress-vulns { margin-left: auto; color: #e6a23c; font-weight: 600; }
.progress-step { font-size: 12px; color: #909399; margin-top: 4px; text-align: right; }
.spin-loader { display: inline-block; width: 14px; height: 14px; border: 2px solid #409EFF; border-top-color: transparent; border-radius: 50%; animation: spin 0.9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
