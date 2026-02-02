import React, { createContext, useContext, useEffect, useState } from 'react';
import { Session } from '@supabase/supabase-js';
import { supabase } from '../lib/supabase';
import { logActivity } from '../lib/activityLog';

type UserRole = 'analyst' | 'admin';

interface AuthContextType {
  session: Session | null;
  user: any;
  loading: boolean;
  authDisabled: boolean;
  role: UserRole;
  switchRole: (role: UserRole) => void;
  signUp: (email: string, password: string) => Promise<any>;
  signIn: (email: string, password: string) => Promise<any>;
  signOut: () => Promise<void>;
  resetPassword: (email: string) => Promise<any>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [role, setRole] = useState<UserRole>('analyst');
  const authDisabled = !supabase;

  useEffect(() => {
    const getSession = async () => {
      if (!supabase) {
        setLoading(false);
        return;
      }

      const { data, error } = await supabase.auth.getSession();
      if (!error && data.session) {
        setSession(data.session);
        setUser(data.session.user);
        const metadataRole = data.session.user.user_metadata?.role;
        if (metadataRole === 'admin' || metadataRole === 'analyst') {
          setRole(metadataRole);
        }
      }
      setLoading(false);
    };

    getSession();

    if (!supabase) {
      return;
    }

    const { data: authListener } = supabase.auth.onAuthStateChange((event, newSession) => {
      setSession(newSession);
      setUser(newSession?.user || null);
      const metadataRole = newSession?.user.user_metadata?.role;
      if (metadataRole === 'admin' || metadataRole === 'analyst') {
        setRole(metadataRole);
      }
    });

    return () => {
      authListener?.subscription.unsubscribe();
    };
  }, []);

  const signUp = async (email: string, password: string) => {
    if (!supabase) {
      return Promise.resolve({ data: null, error: null });
    }

    const result = await supabase.auth.signUp({
      email,
      password,
    });

    await logActivity({
      category: 'auth',
      action: 'signup',
      status: result.error ? 'failure' : 'success',
      description: result.error?.message,
      email,
    });

    return result;
  };

  const signIn = async (email: string, password: string) => {
    if (!supabase) {
      return Promise.resolve({ data: null, error: null });
    }

    const result = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    await logActivity({
      category: 'auth',
      action: 'login',
      status: result.error ? 'failure' : 'success',
      description: result.error?.message,
      email,
    });

    return result;
  };

  const signOut = async () => {
    if (!supabase) {
      setSession(null);
      setUser(null);
      setRole('analyst');
      return;
    }

    const { error } = await supabase.auth.signOut();

    await logActivity({
      category: 'auth',
      action: 'logout',
      status: error ? 'failure' : 'success',
      description: error?.message,
      email: user?.email,
    });
  };

  const resetPassword = async (email: string) => {
    if (!supabase) {
      return Promise.resolve({ data: null, error: null });
    }

    const result = await supabase.auth.resetPasswordForEmail(email);

    await logActivity({
      category: 'auth',
      action: 'reset_password',
      status: result.error ? 'failure' : 'success',
      description: result.error?.message,
      email,
    });

    return result;
  };

  const value: AuthContextType = {
    session,
    user,
    loading,
    authDisabled,
    role,
    switchRole: (nextRole: UserRole) => {
      if (nextRole !== role && (nextRole === 'analyst' || nextRole === 'admin')) {
        if (authDisabled) {
          setRole(nextRole);
        }
      }
    },
    signUp,
    signIn,
    signOut,
    resetPassword,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
