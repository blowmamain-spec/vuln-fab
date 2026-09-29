export async function search(q: string) {
  const a = await supabase.from("todos").select("*").ilike("title", `%${q}%`);
  const b = await supabase.from("todos").select("*").or("done.eq.true,priority.gte.3");
  const c = await supabase.from("todos").select("*").or(filter);
  return [a, b, c];
}
