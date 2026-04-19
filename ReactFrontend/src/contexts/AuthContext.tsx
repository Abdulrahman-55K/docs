import React, { createContext, useContext, useEffect, useState } from "react";
import {
  apiPost,
  apiGet,
  setTokens,
  clearTokens,
  getAccessToken,
} from "../lib/api";

type UserRole = "analyst" | "admin";

interface User {
  id: string;
  email: string;
  role: UserRole;
  is_verified: boolean;
  created_at: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  role: UserRole;
  signUp: (
    email: string,
    password: string,
    passwordConfirm: string
  ) => Promise<{ error?: string }>;
  signIn: (
    email: string,
    password: string
  ) => Promise<{ error?: string }>;
  signOut: () => Promise<void>;
  resetPassword: (email: string) => Promise<{ error?: string }>;
  resetPasswordConfirm: (
    email: string,
    code: string,
    newPassword: string,
    newPasswordConfirm: string
  ) => Promise<{ error?: string }>;
  verifyOTP: (
    email: string,
    code: string,
    purpose: string
  ) => Promise<{ error?: string }>;
  resendOTP: (
    email: string,
    purpose: string
  ) => Promise<{ error?: string }>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [role, setRole] = useState<UserRole>("analyst");

  // On mount, check if we have a valid token and fetch user profile
  useEffect(() => {
    const initAuth = async () => {
      const token = getAccessToken();
      if (!token) {
        setLoading(false);
        return;
      }

      const { data, error } = await apiGet<User>("/auth/me/");
      if (data && !error) {
        setUser(data);
        setRole(data.role);
      } else {
        // Token expired or invalid
        clearTokens();
      }
      setLoading(false);
    };

    initAuth();
  }, []);

  const signUp = async (
    email: string,
    password: string,
    passwordConfirm: string
  ) => {
    const { data, error } = await apiPost("/auth/signup/", {
      email,
      password,
      password_confirm: passwordConfirm,
    });
    if (error) return { error };
    return {};
  };

  const verifyOTP = async (email: string, code: string, purpose: string) => {
    const { data, error } = await apiPost("/auth/verify-otp/", {
      email,
      code,
      purpose,
    });
    if (error) return { error };
    return {};
  };

  const resendOTP = async (email: string, purpose: string) => {
    const { data, error } = await apiPost("/auth/resend-otp/", {
      email,
      purpose,
    });
    if (error) return { error };
    return {};
  };

  const signIn = async (email: string, password: string) => {
    const { data, error } = await apiPost<{
      tokens: { access: string; refresh: string };
      user: User;
    }>("/auth/login/", { email, password });

    if (error) return { error };
    if (data) {
      setTokens(data.tokens.access, data.tokens.refresh);
      setUser(data.user);
      setRole(data.user.role);
    }
    return {};
  };

  const signOut = async () => {
    const refreshToken = localStorage.getItem("refresh_token");
    if (refreshToken) {
      await apiPost("/auth/logout/", { refresh: refreshToken });
    }
    clearTokens();
    setUser(null);
    setRole("analyst");
  };

  const resetPassword = async (email: string) => {
    const { data, error } = await apiPost("/auth/password-reset/", { email });
    if (error) return { error };
    return {};
  };

  const resetPasswordConfirm = async (
    email: string,
    code: string,
    newPassword: string,
    newPasswordConfirm: string
  ) => {
    const { data, error } = await apiPost("/auth/password-reset/confirm/", {
      email,
      code,
      new_password: newPassword,
      new_password_confirm: newPasswordConfirm,
    });
    if (error) return { error };
    return {};
  };

  const value: AuthContextType = {
    user,
    loading,
    role,
    signUp,
    signIn,
    signOut,
    resetPassword,
    resetPasswordConfirm,
    verifyOTP,
    resendOTP,
  };

  return (
    <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
