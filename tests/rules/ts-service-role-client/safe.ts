import { createClient } from "@supabase/supabase-js";

export const a = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
export const b = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);
export const c = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
export const d = createClient(url, import.meta.env.VITE_SUPABASE_ANON_KEY);
