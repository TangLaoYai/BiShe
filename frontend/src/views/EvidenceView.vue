<template>
  <div>
    <el-card shadow="never" style="margin-bottom:15px">
      <el-form inline @submit.prevent>
        <el-form-item label="哈希地址">
          <el-input v-model="hashKeyword" placeholder="tx/contract/audit hash 前缀"
                    clearable style="width:380px" @keyup.enter="doSearch" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="doSearch">查 询</el-button>
          <el-button @click="doReset">重 置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never">
      <template #header><span>历史存证记录（FISCO BCOS 上链）</span></template>
      <el-table :data="items" v-loading="loading" stripe>
        <el-table-column prop="audit_id" label="审计ID" min-width="230" />
        <el-table-column prop="contract_name" label="合约名称" min-width="140" />
        <el-table-column prop="chain_time" label="上链时间" width="170" />
        <el-table-column label="交易哈希" min-width="300">
          <template #default="{ row }">
            <span class="tx-hash">{{ row.tx_hash }}</span>
            <el-button link type="primary" size="small" @click="copyTx(row.tx_hash)">复制</el-button>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="110" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="$router.push(`/audits/${row.audit_id}`)">查看审计</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination style="margin-top:14px; justify-content:flex-end" layout="total, prev, pager, next, jumper"
                     :total="total" :page-size="page_size" :current-page="page"
                     @current-change="changePage" />
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const items = ref([])
const total = ref(0)
const page = ref(1)
const page_size = 10
const loading = ref(false)
const hashKeyword = ref('')

async function loadList() {
  loading.value = true
  try {
    const data = await api.get('/evidence', {
      params: { page: page.value, page_size, hash: hashKeyword.value }
    })
    items.value = data.items
    total.value = data.total
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function doSearch() {
  page.value = 1
  loadList()
}

function doReset() {
  hashKeyword.value = ''
  page.value = 1
  loadList()
}

function changePage(p) {
  page.value = p
  loadList()
}

function copyTx(hash) {
  navigator.clipboard.writeText(hash)
  ElMessage.success('交易哈希已复制')
}

onMounted(loadList)
</script>
