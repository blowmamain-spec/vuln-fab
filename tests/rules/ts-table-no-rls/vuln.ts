import { createClient } from "@supabase/supabase-js";

const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

export async function a() {
  return supabase.from("open_table").select("*"); // vuln: ts-table-no-rls
}

export async function b() {
  await supabase.from("cfg").insert({ id: 1 }); // vuln: ts-table-no-rls
}

export async function c() {
  const { data } = await supabase // vuln: ts-table-no-rls
    .from("open_table")
    .update({ note: "x" })
    .eq("id", 1);
  return data;
}
