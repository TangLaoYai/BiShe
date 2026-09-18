import axios from 'axios'

/** 统一 API 客户端：携带 Cookie 会话，401 自动跳登录页 */
const api = axios.create({
  baseURL: '/api',
  timeout: 60000,
  withCredentials: true,
})

api.interceptors.response.use(
  (resp) => resp.data,
  (err) => {
    const status = err.response?.status
    const msg = err.response?.data?.message || err.message || '请求失败'
    if (status === 401 && !location.pathname.startsWith('/login')) {
      sessionStorage.removeItem('cas_user')
      window.location.href = '/login'
    }
    return Promise.reject(new Error(msg))
  }
)

export default api
