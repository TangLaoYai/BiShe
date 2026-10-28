<template>
  <div class="auth-wrap">
    <el-card class="auth-card">
      <h2 class="auth-title">智能合约漏洞审计系统</h2>
      <el-form :model="form" @keyup.enter="doLogin">
        <el-form-item>
          <el-input v-model="form.username" placeholder="请输入账号" size="large" />
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" type="password" show-password
                    placeholder="请输入密码" size="large" />
        </el-form-item>
        <el-button type="primary" size="large" style="width:100%" :loading="loading"
                   @click="doLogin">登 录</el-button>
        <div class="to-register">
          还没有账号？<el-button link type="primary" @click="$router.push('/register')">立即注册</el-button>
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
import { setUser } from '../store'

const router = useRouter()
const form = reactive({ username: '', password: '' })
const loading = ref(false)

async function doLogin() {
  if (!form.username || !form.password) {
    ElMessage.warning('请输入账号和密码')
    return
  }
  loading.value = true
  try {
    const data = await api.post('/auth/login', form)
    setUser(data.user)
    ElMessage.success('登录成功')
    router.push('/contracts')
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
  background: url('../assets/login-bg.jpg') center/cover no-repeat;
}
/* 不用图片时，把上一行注释掉，启用这一行：
  background: linear-gradient(135deg, #1f2a48 0%, #2c4a7c 50%, #3b6ea5 100%);
*/
.auth-card {
  width: 380px; padding: 10px 15px;
  background-color: rgba(255, 255, 255, 0.92);
  backdrop-filter: blur(8px);
  border-radius: 8px;
}
.auth-title { text-align: center; margin-bottom: 25px; color: #303133; }
.to-register { text-align: center; margin-top: 12px; font-size: 14px; color: #909399; }
</style>

