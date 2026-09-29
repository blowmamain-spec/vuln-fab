export async function search(q: string) {
  const a = await supabase.from("todos").select("*").or(`title.ilike.%${q}%,body.ilike.%${q}%`); // vuln: ts-supabase-or-inject
  const b = await supabase.from("todos").select("*").or("title.eq." + q); // vuln: ts-supabase-or-inject
  return [a, b];
}
