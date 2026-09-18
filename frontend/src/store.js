import { reactive } from 'vue'
import api from './api'

/** 全局用户状态（Session 会话，页面刷新时通过 /auth/me 恢复） */
export const store = reactive({
  user: null,
  loaded: false,
})

export async function loadUser() {
  if (store.loaded) return store.user
  try {
    store.user = await api.get('/auth/me')
    sessionStorage.setItem('cas_user', JSON.stringify(store.user))
  } catch {
    store.user = null
    sessionStorage.removeItem('cas_user')
  }
  store.loaded = true
  return store.user
}

export function setUser(user) {
  store.user = user
  store.loaded = true
  sessionStorage.setItem('cas_user', JSON.stringify(user))
}

export function clearUser() {
  store.user = null
  store.loaded = true
  sessionStorage.removeItem('cas_user')
}

export const isAdmin = () => store.user?.role === 'admin'
