import { createClient } from "@supabase/supabase-js";

const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function a(params: { id: string }) {
  return supabase.from("invoices").select("*").eq("id", params.id).single(); // vuln: ts-idor-eq-id
}

export async function b(req: Req) {
  return admin.from("todos").delete().eq("id", req.query.id); // vuln: ts-idor-eq-id
}

export async function c(searchParams: URLSearchParams) {
  return supabase.from("docs").select("*").eq("id", searchParams.get("id")); // vuln: ts-idor-eq-id
}
