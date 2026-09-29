import { createClient } from "@supabase/supabase-js";

const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function a() {
  await supabase.from("closed_table").select("*");
  await admin.from("open_table").select("*");
  await supabase.from("not_in_migrations").select("*");
  await supabase.from("hidden").select("*");
  supabase.storage.from("avatars").upload("a", file);
  const xs = Array.from(items);
}
