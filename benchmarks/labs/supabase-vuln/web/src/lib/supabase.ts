import { createClient } from "@supabase/supabase-js";

const url = process.env.NEXT_PUBLIC_SUPABASE_URL!;

// @lab decoy service-role-client cwe=CWE-522 :: kunci anon
export const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

// @lab vuln service-role-client cwe=CWE-522 tier=A :: kunci service_role di kode frontend
export const supabaseAdmin = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
