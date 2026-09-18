<template>
  <div v-loading="loading">
    <!-- 数字卡片 -->
    <el-row :gutter="15" style="margin-bottom:15px">
      <el-col :span="4" v-for="card in cardList" :key="card.key">
        <el-card shadow="hover" :body-style="{ padding: '18px' }">
          <div class="card-label">{{ card.label }}</div>
          <div class="card-value" :style="{ color: card.color }">{{ card.value }}</div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 趋势 + 饼图 -->
    <el-row :gutter="15" style="margin-bottom:15px">
      <el-col :span="14">
        <el-card shadow="never">
          <template #header><span>近 7 天审计趋势</span></template>
          <div ref="trendRef" style="height:300px"></div>
        </el-card>
      </el-col>
      <el-col :span="10">
        <el-card shadow="never">
          <template #header><span>漏洞等级分布</span></template>
          <div ref="pieRef" style="height:300px"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Top5 -->
    <el-card shadow="never">
      <template #header><span>Top 5 漏洞类型</span></template>
      <div ref="barRef" style="height:320px"></div>
    </el-card>
  </div>
</template>

<script setup>
import { onMounted, onBeforeUnmount, ref, reactive, computed, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import * as echarts from 'echarts'
import api from '../api'
import { store } from '../store'

const loading = ref(false)
const trendRef = ref(null)
const pieRef = ref(null)
const barRef = ref(null)
let trendChart, pieChart, barChart

const cards = reactive({
  contracts: 0, audits: 0, running: 0,
  high_vulns: 0, evidence: 0, users: 0,
})

const cardList = computed(() => {
  const base = [
    { key: 'contracts', label: '合约总数', value: cards.contracts, color: '#409EFF' },
    { key: 'audits', label: '审计总数', value: cards.audits, color: '#67C23A' },
    { key: 'running', label: '进行中', value: cards.running, color: '#E6A23C' },
    { key: 'high_vulns', label: '高危漏洞', value: cards.high_vulns, color: '#F56C6C' },
    { key: 'evidence', label: '存证数', value: cards.evidence, color: '#909399' },
  ]
  if (store.user?.role === 'admin') {
    base.push({ key: 'users', label: '用户数', value: cards.users, color: '#9B59B6' })
  }
  return base
})

async function loadDashboard() {
  loading.value = true
  try {
    const data = await api.get('/stats/dashboard')
    Object.assign(cards, data.cards)
    await nextTick()
    renderTrend(data.trend)
    renderPie(data.risk_pie)
    renderBar(data.top_vulns)
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}

function renderTrend(trend) {
  if (!trendRef.value) return
  if (!trendChart) trendChart = echarts.init(trendRef.value)
  trendChart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 20, top: 30, bottom: 30 },
    xAxis: { type: 'category', data: trend.map(t => t.date), boundaryGap: false },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{
      name: '审计数', type: 'line', smooth: true,
      data: trend.map(t => t.count),
      itemStyle: { color: '#409EFF' },
      areaStyle: { color: 'rgba(64,158,255,0.15)' },
    }],
  })
}

function renderPie(pie) {
  if (!pieRef.value) return
  if (!pieChart) pieChart = echarts.init(pieRef.value)
  const colorMap = { '高危': '#F56C6C', '中危': '#E6A23C', '低危': '#67C23A' }
  pieChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0 },
    series: [{
      type: 'pie', radius: ['40%', '70%'],
      data: pie.map(p => ({ ...p, itemStyle: { color: colorMap[p.name] } })),
      label: { formatter: '{b}\n{c}' },
    }],
  })
}

function renderBar(top) {
  if (!barRef.value) return
  if (!barChart) barChart = echarts.init(barRef.value)
  barChart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 120, right: 30, top: 20, bottom: 30 },
    xAxis: { type: 'value', minInterval: 1 },
    yAxis: {
      type: 'category',
      data: top.map(t => t.name).reverse(),
      axisLabel: { interval: 0 },
    },
    series: [{
      type: 'bar',
      data: top.map(t => t.value).reverse(),
      itemStyle: { color: '#9B59B6', borderRadius: [0, 4, 4, 0] },
      label: { show: true, position: 'right' },
    }],
  })
}

function handleResize() {
  trendChart?.resize()
  pieChart?.resize()
  barChart?.resize()
}

onMounted(() => {
  loadDashboard()
  window.addEventListener('resize', handleResize)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  trendChart?.dispose()
  pieChart?.dispose()
  barChart?.dispose()
})
</script>

<style scoped>
.card-label { font-size: 13px; color: #909399; margin-bottom: 6px; }
.card-value { font-size: 28px; font-weight: bold; line-height: 1; }
</style>
