<template>
  <el-container style="min-height: 100vh">
    <el-aside width="220px" style="background:#001529">
      <div class="logo">🛡 合约审计系统</div>
      <el-menu :default-active="$route.path" router background-color="#001529"
               text-color="#b7c0cd" active-text-color="#ffffff" style="border-right:none">
        <el-menu-item index="/dashboard">
          <el-icon><DataLine /></el-icon><span>系统总览</span>
        </el-menu-item>
        <el-menu-item index="/contracts">
          <el-icon><Document /></el-icon><span>合约管理</span>
        </el-menu-item>
        <el-menu-item index="/audits">
          <el-icon><Search /></el-icon><span>审计记录</span>
        </el-menu-item>
        <el-menu-item index="/evidence">
          <el-icon><Link /></el-icon><span>存证记录</span>
        </el-menu-item>
        <el-menu-item v-if="store.user?.role === 'admin'" index="/users">
          <el-icon><User /></el-icon><span>用户管理</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <span class="title">{{ $route.meta.title || '智能合约漏洞审计系统' }}</span>
        <div class="user-box">
          <el-tag v-if="store.user?.role === 'admin'" type="danger" size="small">管理员</el-tag>
          <el-tag v-else type="info" size="small">普通用户</el-tag>
          <span class="username">{{ store.user?.username }}</span>
          <el-button link type="primary" @click="logout">退出登录</el-button>
        </div>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { Document, Search, Link, DataLine, User } from '@element-plus/icons-vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'
import { store, clearUser } from '../store'

const router = useRouter()

async function logout() {
  await ElMessageBox.confirm('确定退出登录吗？', '提示', { type: 'warning' })
  try { await api.post('/auth/logout') } catch { /* 忽略 */ }
  clearUser()
  ElMessage.success('已退出登录')
  router.push('/login')
}
</script>

<style scoped>
.logo {
  height: 60px; line-height: 60px; text-align: center;
  color: #fff; font-size: 16px; font-weight: bold;
}
.header {
  background: #fff; display: flex; align-items: center;
  justify-content: space-between; box-shadow: 0 1px 4px rgba(0,21,41,.08);
}
.title { font-size: 16px; font-weight: bold; }
.user-box { display: flex; align-items: center; gap: 10px; }
.username { font-size: 14px; }
</style>
