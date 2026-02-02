import { supabase } from './supabase';

type ActivityCategory =
  | 'auth'
  | 'report'
  | 'admin';

interface ActivityLogPayload {
  category: ActivityCategory;
  action: string;
  status: 'success' | 'failure';
  description?: string;
  email?: string;
}

export async function logActivity(payload: ActivityLogPayload) {
  if (!supabase) {
    return;
  }

  const { category, action, status, description, email } = payload;

  try {
    await supabase.from('activity_log').insert({
      category,
      action,
      status,
      description,
      email,
    });
  } catch (err) {
    // Best-effort only – don't break UX if logging fails
    console.error('Failed to log activity', err);
  }
}

