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
            <el-button type="success" :disabled="!canChain" @click="chainEvidence">
              {{ detail.evidence ? '已上链存证' : '上链存证' }}
            </el-button>
            <el-button type="warning" plain :disabled="!detail.evidence" @click="verifyEvidence">
              存证校验
            </el-button>
          </div>
        </div>
      </template>
      <el-descriptions :column="3" border>
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
let timer = null

const canChain = computed(() => detail.status === '完成' && !detail.evidence)
const statusType = (s) => s === '完成' ? 'success' : s === '失败' ? 'danger' : 'warning'
const levelType = (l) => l === '高危' ? 'danger' : l === '中危' ? 'warning' : 'info'

async function loadDetail(vulnPage = 1) {
  try {
    const data = await api.get(`/audits/${auditId}`, {
      params: { vuln_page: vulnPage, vuln_page_size: 20 }
    })
    Object.assign(detail, data)
    if (data.status === 'running' && !timer) {
      timer = setInterval(() => loadDetail(detail.vulns?.page || 1), 2000)
    }
    if (data.status !== 'running' && timer) {
      clearInterval(timer)
      timer = null
    }
  } catch (e) {
    ElMessage.error(e.message)
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
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.card-header { display: flex; justify-content: space-between; align-items: center; }
</style>
