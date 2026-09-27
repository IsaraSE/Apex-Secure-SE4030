"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Zap, Mail, Lock, Eye, EyeOff } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useGoogleLogin } from "@react-oauth/google";

import PublicNavbar from "@/components/layout/PublicNavbar";

function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const { login, googleLogin } = useAuth();
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await login(email, password);
      router.push("/dashboard");
    } catch (err: any) {
      setError(err.response?.data?.message || "Login failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = useGoogleLogin({
    flow: "implicit",
    onSuccess: async (tokenResponse) => {
      setGoogleLoading(true);
      setError("");
      try {
        // Exchange the access token for user info, then get an id_token via credential endpoint
        const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
          headers: { Authorization: `Bearer ${tokenResponse.access_token}` },
        });
        const userInfo = await res.json();
        // Send user info directly to our backend
        const api = (await import("@/lib/api")).default;
        const backendRes = await api.post("/auth/google-login", {
          credential: tokenResponse.access_token,
          email: userInfo.email,
          name: userInfo.name,
          googleId: userInfo.sub,
        });
        const { accessToken, refreshToken, user: userData } = backendRes.data;
        localStorage.setItem("accessToken", accessToken);
        localStorage.setItem("refreshToken", refreshToken);
        localStorage.setItem("user", JSON.stringify(userData));
        router.push("/dashboard");
        // Force a full reload to update auth state
        window.location.href = "/dashboard";
      } catch (err: any) {
        setError(err.response?.data?.message || "Google Login failed.");
      } finally {
        setGoogleLoading(false);
      }
    },
    onError: () => {
      setError("Google Login failed. Please try again.");
    },
  });

  return (
    <div className="min-h-screen bg-surface-950">
      <PublicNavbar />
      <div className="flex items-center justify-center px-4 py-20 relative">
      {/* Background effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 -left-32 w-96 h-96 bg-brand-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 -right-32 w-96 h-96 bg-brand-700/10 rounded-full blur-3xl" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative w-full max-w-md"
      >
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center shadow-xl shadow-brand-500/20">
            <Zap className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-surface-50 tracking-tight">APEX</h1>
            <p className="text-xs text-surface-500 uppercase tracking-widest">Sports Club</p>
          </div>
        </div>

        {/* Card */}
        <div className="glass-card p-8">
          <div className="text-center mb-8">
            <h2 className="text-xl font-bold text-surface-100">Welcome back</h2>
            <p className="text-sm text-surface-500 mt-1">Sign in to your account</p>
          </div>

          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-6 p-3 rounded-lg bg-danger-500/10 border border-danger-500/20 text-danger-400 text-sm"
            >
              {error}
            </motion.div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-surface-300 mb-2">Email</label>
              <div className="relative">
                <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input-field pl-11"
                  placeholder="admin@apex.lk"
                  required
                  id="login-email"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-surface-300 mb-2">Password</label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-500" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-field pl-11 pr-11"
                  placeholder="••••••••"
                  required
                  id="login-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-surface-500 hover:text-surface-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full flex items-center justify-center gap-2"
              id="login-submit"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                "Sign In"
              )}
            </button>
          </form>

          <div className="mt-6 flex items-center gap-3">
            <span className="flex-1 h-px bg-surface-700/50"></span>
            <span className="text-xs text-surface-500 uppercase tracking-wider font-medium">or continue with</span>
            <span className="flex-1 h-px bg-surface-700/50"></span>
          </div>

          <motion.button
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
            onClick={() => handleGoogleLogin()}
            disabled={googleLoading}
            className="mt-5 w-full flex items-center justify-center gap-3 px-4 py-3 rounded-xl border border-surface-700/50 bg-surface-800/50 hover:bg-surface-700/50 hover:border-surface-600/50 transition-all duration-200 group"
            type="button"
            id="google-login-btn"
          >
            {googleLoading ? (
              <div className="w-5 h-5 border-2 border-surface-400/30 border-t-surface-300 rounded-full animate-spin" />
            ) : (
              <>
                <svg className="w-5 h-5" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                <span className="text-sm font-medium text-surface-300 group-hover:text-surface-100 transition-colors">
                  Continue with Google
                </span>
              </>
            )}
          </motion.button>

          <p className="text-center text-sm text-surface-500 mt-6">
            Don&apos;t have an account?{" "}
            <a href="/register" className="text-brand-400 hover:text-brand-300 font-medium">
              Register
            </a>
          </p>
        </div>

        {/* Demo credentials */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="mt-6 p-4 rounded-xl bg-surface-900/40 border border-surface-800/50"
        >
          <p className="text-xs text-surface-500 font-medium mb-2">Demo Credentials:</p>
          <div className="space-y-1 text-xs text-surface-400">
            <p><span className="text-surface-500">Admin:</span> admin@apex.lk / password123</p>
            <p><span className="text-surface-500">Coach:</span> nimal.coach@apex.lk / password123</p>
            <p><span className="text-surface-500">Member:</span> dinesh@apex.lk / password123</p>
          </div>
        </motion.div>
      </motion.div>
    </div>
  </div>
  );
}

export default function LoginPage() {
  return <LoginForm />;
}
