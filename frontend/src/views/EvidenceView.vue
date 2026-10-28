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
        <el-table-column label="所在区块" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.block_number" type="primary" size="small">#{{ row.block_number }}</el-tag>
            <span v-else style="color:#909399">-</span>
          </template>
        </el-table-column>
        <el-table-column label="交易哈希" min-width="300">
          <template #default="{ row }">
            <span class="tx-hash">{{ row.tx_hash }}</span>
            <el-button link type="primary" size="small" @click="copyTx(row.tx_hash)">复制</el-button>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="$router.push(`/audits/${row.audit_id}`)">查看审计</el-button>
            <el-button link type="success" @click="fetchBlock(row)">查看区块</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination style="margin-top:14px; justify-content:flex-end" layout="total, prev, pager, next, jumper"
                     :total="total" :page-size="page_size" :current-page="page"
                     @current-change="changePage" />
    </el-card>

    <el-dialog v-model="blockVisible" title="链上区块详情" width="560px">
      <el-descriptions :column="1" border>
        <el-descriptions-item label="区块高度">
          <span class="block-num">#{{ blockInfo.block_number || '-' }}</span>
          <el-tag v-if="blockInfo.simulate" type="info" size="small" style="margin-left:8px">模拟链</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="区块时间">{{ blockInfo.time || '-' }}</el-descriptions-item>
        <el-descriptions-item label="所在群组">group {{ blockInfo.group_id ?? '-' }}</el-descriptions-item>
        <el-descriptions-item label="交易数量">{{ blockInfo.tx_count ?? '-' }}</el-descriptions-item>
        <el-descriptions-item label="交易哈希">
          <span class="tx-hash">{{ blockInfo.tx_hash }}</span>
          <el-button link type="primary" size="small" @click="copyTx(blockInfo.tx_hash)">复制</el-button>
        </el-descriptions-item>
      </el-descriptions>
      <p style="margin-top:12px; font-size:12px; color:#909399">
        链浏览器入口：
        <a v-if="blockInfo.block_number" :href="`https://fisco.blockchain.cn/`" target="_blank" rel="noopener">
          FISCO BCOS 链浏览器 ↗
        </a>
        <span v-else>请确认联盟链节点已启动</span>
      </p>
    </el-dialog>
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
const blockVisible = ref(false)
const blockInfo = ref({})

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

function doSearch() { page.value = 1; loadList() }
function doReset() { hashKeyword.value = ''; page.value = 1; loadList() }
function changePage(p) { page.value = p; loadList() }

function copyTx(hash) {
  navigator.clipboard.writeText(hash)
  ElMessage.success('交易哈希已复制')
}

async function fetchBlock(row) {
  try {
    const data = await api.get('/evidence/block', { params: { audit_id: row.audit_id } })
    blockInfo.value = { ...data, tx_hash: row.tx_hash }
    blockVisible.value = true
  } catch (e) {
    ElMessage.error(e.message)
  }
}

onMounted(loadList)
</script>

<style scoped>
.tx-hash { font-family: Consolas, Menlo, monospace; font-size: 12px; color: #409EFF; word-break: break-all; }
.block-num { font-size: 16px; font-weight: bold; color: #67C23A; }
</style>
