<template>
  <el-card shadow="never">
    <template #header><span>用户管理（仅管理员）</span></template>
    <el-table :data="items" v-loading="loading" stripe>
      <el-table-column prop="id" label="ID" width="60" />
      <el-table-column prop="username" label="用户名" min-width="140" />
      <el-table-column label="角色" width="100">
        <template #default="{ row }">
          <el-tag :type="row.role === 'admin' ? 'danger' : 'info'" size="small">
            {{ row.role === 'admin' ? '管理员' : '普通用户' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="100">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'warning'" size="small">
            {{ row.status === 'active' ? '正常' : '已禁用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="contract_count" label="合约数" width="90" />
      <el-table-column prop="audit_count" label="审计数" width="90" />
      <el-table-column prop="create_time" label="创建时间" width="160" />
      <el-table-column label="操作" width="180" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" @click="openDetail(row)">查看详情</el-button>
          <el-button
            :type="row.status === 'active' ? 'warning' : 'success'"
            link
            :disabled="row.id === currentUid"
            @click="toggleStatus(row)">
            {{ row.status === 'active' ? '禁用' : '启用' }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>

  <!-- 用户详情抽屉 -->
  <el-drawer
    v-model="drawerVisible"
    :title="selectedUser ? `用户详情 — ${selectedUser.username}` : '用户详情'"
    size="680px"
    destroy-on-close>
    <template v-if="selectedUser">
      <el-tabs v-model="activeTab" @tab-change="loadTabData">
        <!-- 合约 Tab -->
        <el-tab-pane label="上传的合约" name="contracts">
          <el-table :data="contracts" v-loading="contractLoading" stripe size="small" empty-text="该用户未上传合约">
            <el-table-column prop="id" label="ID" width="60" />
            <el-table-column prop="contract_name" label="合约名称" min-width="180" />
            <el-table-column prop="function_count" label="函数数" width="80" />
            <el-table-column prop="upload_time" label="上传时间" width="160" />
          </el-table>
        </el-tab-pane>

        <!-- 审计 Tab -->
        <el-tab-pane label="审计记录" name="audits">
          <el-table :data="audits" v-loading="auditLoading" stripe size="small" empty-text="该用户未发起审计">
            <el-table-column label="审计编号" width="220">
              <template #default="{ row }">{{ row.audit_id }}</template>
            </el-table-column>
            <el-table-column label="合约" min-width="140">
              <template #default="{ row }">{{ row.contract_name }}</template>
            </el-table-column>
            <el-table-column label="状态" width="90">
              <template #default="{ row }">
                <el-tag :type="row.status === '已完成' ? 'success' : (row.status === '运行中' ? 'warning' : 'danger')" size="small">
                  {{ row.status }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="综合风险" width="90">
              <template #default="{ row }">
                <el-tag v-if="row.risk_level" :type="{'高危':'danger','中危':'warning','低危':'info'}[row.risk_level] || 'info'" size="small">
                  {{ row.risk_level }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="audit_time" label="审计时间" width="160" />
          </el-table>
        </el-tab-pane>

        <!-- 存证 Tab -->
        <el-tab-pane label="链上存证" name="evidence">
          <el-table :data="evidences" v-loading="evidenceLoading" stripe size="small" empty-text="该用户未发起存证">
            <el-table-column label="审计编号" width="220">
              <template #default="{ row }">{{ row.audit_id }}</template>
            </el-table-column>
            <el-table-column label="交易哈希" min-width="260">
              <template #default="{ row }">
                <code style="font-size:12px">{{ row.tx_hash || '(未上链)' }}</code>
              </template>
            </el-table-column>
            <el-table-column prop="block_number" label="区块高度" width="100" />
            <el-table-column prop="create_time" label="存证时间" width="160" />
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </template>
  </el-drawer>
</template>

<script setup>
import { onMounted, ref, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'
import { store } from '../store'

const items = ref([])
const loading = ref(false)
const currentUid = computed(() => store.user?.user_id)

// 抽屉状态
const drawerVisible = ref(false)
const selectedUser = ref(null)
const activeTab = ref('contracts')
const contracts = ref([]); const contractLoading = ref(false)
const audits = ref([]); const auditLoading = ref(false)
const evidences = ref([]); const evidenceLoading = ref(false)

async function loadList() {
  loading.value = true
  try {
    const data = await api.get('/users')
    items.value = data.items
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

async function toggleStatus(row) {
  const action = row.status === 'active' ? '禁用' : '启用'
  await ElMessageBox.confirm(`确认${action}账号 "${row.username}" 吗？`, '提示', { type: 'warning' })
  try {
    const res = await api.post(`/users/${row.id}/toggle-status`)
    ElMessage.success(res.message)
    row.status = res.status
  } catch (e) {
    ElMessage.error(e.message)
  }
}

function openDetail(row) {
  selectedUser.value = row
  activeTab.value = 'contracts'
  drawerVisible.value = true
  setTimeout(() => loadTabData(), 0)
}

async function loadTabData() {
  if (!selectedUser.value) return
  const uid = selectedUser.value.id
  if (activeTab.value === 'contracts') {
    contractLoading.value = true
    try {
      const data = await api.get('/contracts', { params: { user_id: uid, page_size: 50 } })
      contracts.value = data.items || []
    } catch (e) { contracts.value = [] }
    finally { contractLoading.value = false }
  } else if (activeTab.value === 'audits') {
    auditLoading.value = true
    try {
      const data = await api.get('/audits', { params: { user_id: uid, page_size: 50 } })
      audits.value = data.items || []
    } catch (e) { audits.value = [] }
    finally { auditLoading.value = false }
  } else if (activeTab.value === 'evidence') {
    evidenceLoading.value = true
    try {
      const data = await api.get('/evidence', { params: { user_id: uid, page_size: 50 } })
      evidences.value = data.items || []
    } catch (e) { evidences.value = [] }
    finally { evidenceLoading.value = false }
  }
}

onMounted(loadList)
</script>
