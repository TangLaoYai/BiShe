import { createRouter, createWebHistory } from 'vue-router'
import { loadUser } from './store'
import Layout from './components/Layout.vue'

const routes = [
  { path: '/login', component: () => import('./views/LoginView.vue'), meta: { title: '登录' } },
  { path: '/register', component: () => import('./views/RegisterView.vue'), meta: { title: '注册' } },
  {
    path: '/',
    component: Layout,
    children: [
      { path: '', redirect: '/dashboard' },
      { path: 'dashboard', component: () => import('./views/DashboardView.vue'), meta: { title: '系统总览' } },
      { path: 'contracts', component: () => import('./views/ContractsView.vue'), meta: { title: '合约管理' } },
      { path: 'audits', component: () => import('./views/AuditsView.vue'), meta: { title: '审计记录' } },
      { path: 'audits/:auditId', component: () => import('./views/AuditDetailView.vue'), meta: { title: '审计详情' } },
      { path: 'evidence', component: () => import('./views/EvidenceView.vue'), meta: { title: '存证记录' } },
      { path: 'users', component: () => import('./views/UsersView.vue'), meta: { title: '用户管理', requireAdmin: true } },
    ],
  },
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(async (to) => {
  const user = await loadUser()
  if (!user && to.path !== '/login' && to.path !== '/register') {
    return '/login'
  }
  if (user && (to.path === '/login' || to.path === '/register')) {
    return '/dashboard'
  }
  // 管理员页面权限拦截
  if (to.meta.requireAdmin && user?.role !== 'admin') {
    return '/dashboard'
  }
  document.title = to.meta.title ? `${to.meta.title} - 智能合约漏洞审计系统` : '智能合约漏洞审计系统'
  return true
})

export default router
