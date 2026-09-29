import { createClient } from "@supabase/supabase-js";

export const a = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!); // vuln: ts-service-role-client
export const b = createClient(url, process.env["VITE_SUPABASE_SERVICE_ROLE_KEY"] as string); // vuln: ts-service-role-client
export const c = createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_KEY); // vuln: ts-service-role-client
