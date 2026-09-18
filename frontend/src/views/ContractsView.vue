<template>
  <div>
    <el-card shadow="never" style="margin-bottom:15px">
      <el-upload drag accept=".sol" :show-file-list="false" :http-request="doUpload">
        <el-icon size="42" color="#409eff"><UploadFilled /></el-icon>
        <div class="el-upload__text">拖拽 .sol 合约文件到此处，或 <em>点击上传</em></div>
        <template #tip>
          <div class="el-upload__tip">仅支持 .sol 格式智能合约文件，上传后自动解析函数列表</div>
        </template>
      </el-upload>
    </el-card>

    <el-card shadow="never">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px">
        <el-input v-model="keyword" placeholder="按合约名前缀搜索" clearable style="width:260px"
                  @keyup.enter="onSearch" @clear="onSearch" />
        <el-button type="primary" plain @click="onSearch">搜索</el-button>
      </div>
      <el-table :data="items" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="contract_name" label="合约名称" min-width="180" />
        <el-table-column prop="function_count" label="函数数量" width="100" />
        <el-table-column prop="upload_time" label="上传时间（精确到分钟）" width="200" />
        <el-table-column v-if="isAdmin()" prop="uploader" label="上传用户" width="120" />
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="showDetail(row)">查看解析</el-button>
            <el-button link type="success" :disabled="!row.can_audit"
                       @click="startAudit(row)">发起审计</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="total > pageSize" style="margin-top:12px; text-align:right">
        <el-pagination background layout="prev, pager, next, total"
                       :total="total" :page-size="pageSize"
                       :current-page="page" @current-change="onPageChange" />
      </div>
    </el-card>

    <el-dialog v-model="detailVisible" :title="`合约解析详情：${detail.contract_name}`" width="860px">
      <el-descriptions :column="3" border size="small" style="margin-bottom:12px">
        <el-descriptions-item label="合约ID">{{ detail.id }}</el-descriptions-item>
        <el-descriptions-item label="合约名称">{{ detail.contract_name }}</el-descriptions-item>
        <el-descriptions-item label="上传时间">{{ detail.upload_time }}</el-descriptions-item>
      </el-descriptions>
      <h4>函数列表（{{ detail.functions?.length || 0 }}）</h4>
      <el-table :data="detail.functions || []" size="small" border max-height="360">
        <el-table-column prop="line" label="行号" width="70" />
        <el-table-column prop="name" label="函数名" min-width="130" />
        <el-table-column prop="visibility" label="可见性" width="90" />
        <el-table-column prop="mutability" label="可变性" width="90" />
        <el-table-column prop="params_text" label="参数" min-width="180" />
        <el-table-column label="修饰符" min-width="120">
          <template #default="{ row }">
            <el-tag v-for="m in row.modifiers" :key="m" size="small" style="margin-right:4px">{{ m }}</el-tag>
          </template>
        </el-table-column>
      </el-table>
      <h4 v-if="detail.audits?.length">历史审计</h4>
      <el-table v-if="detail.audits?.length" :data="detail.audits" size="small" border max-height="200">
        <el-table-column prop="audit_id" label="审计编号" min-width="240" />
        <el-table-column prop="audit_time" label="审计时间" width="170" />
        <el-table-column prop="status" label="状态" width="90" />
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { UploadFilled } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'
import { isAdmin } from '../store'

const router = useRouter()
const items = ref([])
const loading = ref(false)
const detailVisible = ref(false)
const detail = reactive({})
const keyword = ref('')
const page = ref(1)
const pageSize = 10
const total = ref(0)

async function loadList() {
  loading.value = true
  try {
    const data = await api.get('/contracts', {
      params: { keyword: keyword.value, page: page.value, page_size: pageSize }
    })
    items.value = data.items
    total.value = data.total
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function onSearch() {
  page.value = 1
  loadList()
}

function onPageChange(p) {
  page.value = p
  loadList()
}

async function doUpload(opt) {
  const fd = new FormData()
  fd.append('file', opt.file)
  try {
    const data = await api.post('/contracts', fd)
    ElMessage.success(`上传成功：${data.contract_name}，解析出 ${data.functions.length} 个函数`)
    page.value = 1  // 新上传的合约在最新一页(按ID倒序=第1页)
    loadList()
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function showDetail(row) {
  try {
    const data = await api.get(`/contracts/${row.id}`)
    Object.assign(detail, data)
    detailVisible.value = true
  } catch (e) {
    ElMessage.error(e.message)
  }
}

async function startAudit(row) {
  try {
    await ElMessageBox.confirm(
      `确定对合约【${row.contract_name}】发起智能审计吗？将执行静态扫描与渗透探测。`, '发起审计',
      { type: 'info', confirmButtonText: '开始审计' })
    const data = await api.post('/audits', { contract_id: row.id })
    ElMessage.success('审计任务已启动')
    router.push(`/audits/${data.audit_id}`)
  } catch (e) {
    if (e !== 'cancel' && e?.message) ElMessage.error(e.message)
  }
}

onMounted(loadList)
</script>

<style scoped>
.el-upload__text em { color: #409eff; }
</style>
