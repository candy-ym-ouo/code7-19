import { createRouter, createWebHistory } from "vue-router";
import { useAuthStore } from "../stores/auth";

const MapPage = () => import("../pages/MapPage.vue");
const FeatureDetailPage = () => import("../pages/FeatureDetailPage.vue");
const SubmitPage = () => import("../pages/SubmitPage.vue");
const LoginPage = () => import("../pages/LoginPage.vue");
const RegisterPage = () => import("../pages/RegisterPage.vue");
const VerifyEmailPage = () => import("../pages/VerifyEmailPage.vue");
const ResetPasswordPage = () => import("../pages/ResetPasswordPage.vue");
const ContributionsPage = () => import("../pages/ContributionsPage.vue");
const NotificationsPage = () => import("../pages/NotificationsPage.vue");
const CommentsPage = () => import("../pages/CommentsPage.vue");
const SettingsPage = () => import("../pages/SettingsPage.vue");
const ModerationPage = () => import("../pages/ModerationPage.vue");
const DeletionCertificatePage = () => import("../pages/DeletionCertificatePage.vue");

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", redirect: "/map" },
    { path: "/map", name: "map", component: MapPage },
    { path: "/features/:id", name: "feature", component: FeatureDetailPage },
    { path: "/submit", name: "submit", component: SubmitPage, meta: { requiresAuth: true, requiresVerified: true } },
    { path: "/submit/:id", name: "submit-edit", component: SubmitPage, meta: { requiresAuth: true, requiresVerified: true } },
    { path: "/login", name: "login", component: LoginPage },
    { path: "/register", name: "register", component: RegisterPage },
    { path: "/verify-email", name: "verify-email", component: VerifyEmailPage },
    { path: "/reset-password", name: "reset-password", component: ResetPasswordPage },
    { path: "/me/contributions", name: "contributions", component: ContributionsPage, meta: { requiresAuth: true } },
    { path: "/me/comments", name: "comments", component: CommentsPage, meta: { requiresAuth: true } },
    { path: "/me/notifications", name: "notifications", component: NotificationsPage, meta: { requiresAuth: true } },
    { path: "/me/settings", name: "settings", component: SettingsPage, meta: { requiresAuth: true } },
    { path: "/moderation", name: "moderation", component: ModerationPage, meta: { requiresAuth: true, requiresModerator: true } },
    { path: "/compliance/deletion/:id", name: "deletion-certificate", component: DeletionCertificatePage, meta: { requiresAuth: true } },
    { path: "/:pathMatch(.*)*", redirect: "/map" }
  ],
  scrollBehavior: () => ({ top: 0 })
});

router.beforeEach((to) => {
  const auth = useAuthStore();
  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    return { name: "login", query: { redirect: to.fullPath } };
  }
  if (to.meta.requiresVerified && !auth.isVerified) {
    return { name: "login", query: { verify: "1", redirect: to.fullPath } };
  }
  if (to.meta.requiresModerator && !auth.canModerate) {
    return { name: "map" };
  }
  return true;
});
