<template>
  <div>
    <el-card shadow="never" style="margin-bottom:15px">
      <el-form inline @submit.prevent>
        <el-form-item label="审计编号">
          <el-input v-model="query.audit_id" placeholder="输入审计编号前缀" clearable
                    style="width:240px" @keyup.enter="doSearch" />
        </el-form-item>
        <el-form-item label="合约名称">
          <el-input v-model="query.keyword" placeholder="模糊搜索合约名称" clearable
                    style="width:200px" @keyup.enter="doSearch" />
        </el-form-item>
        <el-form-item label="风险等级">
          <el-select v-model="query.level" placeholder="全部" clearable style="width:130px">
            <el-option label="高危" value="高危" />
            <el-option label="中危" value="中危" />
            <el-option label="低危" value="低危" />
          </el-select>
        </el-form-item>
        <el-form-item label="审计时间">
          <el-date-picker v-model="timeRange" type="datetimerange"
                          start-placeholder="开始时间" end-placeholder="结束时间"
                          format="YYYY-MM-DD HH:mm" value-format="YYYY-MM-DD HH:mm" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="doSearch">查 询</el-button>
          <el-button @click="doReset">重 置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never">
      <el-table :data="items" v-loading="loading" stripe>
        <el-table-column prop="audit_id" label="审计编号" min-width="230" />
        <el-table-column prop="contract_name" label="合约名称" min-width="140" />
        <el-table-column prop="audit_time" label="审计时间" width="170" />
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="statusType(row.status)" size="small">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="高危" width="70">
          <template #default="{ row }">
            <el-tag v-if="row.high" type="danger" size="small">{{ row.high }}</el-tag>
            <span v-else>0</span>
          </template>
        </el-table-column>
        <el-table-column label="中危" width="70">
          <template #default="{ row }">
            <el-tag v-if="row.medium" type="warning" size="small">{{ row.medium }}</el-tag>
            <span v-else>0</span>
          </template>
        </el-table-column>
        <el-table-column label="低危" width="70">
          <template #default="{ row }">
            <el-tag v-if="row.low" type="info" size="small">{{ row.low }}</el-tag>
            <span v-else>0</span>
          </template>
        </el-table-column>
        <el-table-column v-if="isAdmin()" prop="uploader" label="执行用户" width="110" />
        <el-table-column label="操作" width="100" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="$router.push(`/audits/${row.audit_id}`)">查看详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination style="margin-top:14px; justify-content:flex-end" layout="total, prev, pager, next, jumper"
                     :total="total" :page-size="query.page_size"
                     :current-page="query.page" @current-change="changePage" />
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'
import { isAdmin } from '../store'

const query = reactive({ audit_id: '', keyword: '', level: '', start_time: '', end_time: '', page: 1, page_size: 10 })
const timeRange = ref(null)
const items = ref([])
const total = ref(0)
const loading = ref(false)

const statusType = (s) => s === '完成' ? 'success' : s === '失败' ? 'danger' : 'warning'

async function loadList() {
  loading.value = true
  try {
    const data = await api.get('/audits', { params: query })
    items.value = data.items
    total.value = data.total
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function doSearch() {
  query.page = 1
  query.start_time = timeRange.value?.[0] || ''
  query.end_time = timeRange.value?.[1] || ''
  loadList()
}

function doReset() {
  query.audit_id = ''
  query.keyword = ''
  query.level = ''
  timeRange.value = null
  doSearch()
}

function changePage(p) {
  query.page = p
  loadList()
}

onMounted(loadList)
</script>
