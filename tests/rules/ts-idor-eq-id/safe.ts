import { createClient } from "@supabase/supabase-js";

const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function a(params: { id: string }, user: User) {
  await supabase.from("invoices").select("*").eq("id", params.id).eq("user_id", user.id);
  await supabase.from("todos").select("*").eq("id", params.id);
  await supabase.from("categories").select("*").eq("id", params.id);
  await admin.from("todos").delete().eq("id", params.id).eq("user_id", user.id);
  await supabase.from("invoices").select("*").eq("id", 5);
  await supabase.from("invoices").select("*").eq("status", params.id);
  await supabase.from("invoices").insert({ id: params.id });
}
