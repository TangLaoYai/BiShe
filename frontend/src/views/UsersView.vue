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
      <el-table-column label="操作" width="120" fixed="right">
        <template #default="{ row }">
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
</template>

<script setup>
import { onMounted, ref, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'
import { store } from '../store'

const items = ref([])
const loading = ref(false)
const currentUid = computed(() => store.user?.user_id)

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

onMounted(loadList)
</script>
