<template>
  <div class="auth-wrap">
    <el-card class="auth-card">
      <h2 class="auth-title">用户注册</h2>
      <el-form :model="form" @keyup.enter="doRegister">
        <el-form-item>
          <el-input v-model="form.username" placeholder="请输入账号（3-50位字母/数字/下划线/中文）" size="large" />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" show-password
                    placeholder="请输入密码（至少6位）" size="large" />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.confirm" type="password" show-password
                    placeholder="请再次输入密码" size="large" />
        </el-form-item>
        <el-button type="primary" size="large" style="width:100%" :loading="loading"
                   @click="doRegister">注 册</el-button>
        <div class="to-login">
          已有账号？<el-button link type="primary" @click="$router.push('/login')">返回登录</el-button>
        </div>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '../api'

const router = useRouter()
const form = reactive({ username: '', password: '', confirm: '' })
const loading = ref(false)

async function doRegister() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入账号和密码')
    return
  }
  if (form.password !== form.confirm) {
    ElMessage.warning('两次输入的密码不一致')
    return
  }
  loading.value = true
  try {
    await api.post('/auth/register', { username: form.username, password: form.password })
    ElMessage.success('注册成功，请登录')
    router.push('/login')
  } catch (e) {
    ElMessage.error(e.message)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.auth-wrap {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, #1f3a5f 0%, #10182b 100%);
}
.auth-card { width: 400px; padding: 10px 15px; }
.auth-title { text-align: center; margin-bottom: 25px; color: #303133; }
.to-login { text-align: center; margin-top: 12px; font-size: 14px; color: #909399; }
</style>
