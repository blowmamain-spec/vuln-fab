import type { NextApiRequest, NextApiResponse } from "next";
import { supabase } from "../../lib/supabase";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const q = String(req.query.q);
  // @lab vuln or-inject cwe=CWE-943 tier=A lines=4 :: input masuk ke filter PostgREST .or()
  const a = await supabase
    .from("todos")
    .select("*")
    .or(`title.ilike.%${q}%,body.ilike.%${q}%`);
  // @lab decoy or-inject cwe=CWE-943 :: filter terparameter
  const b = await supabase.from("todos").select("*").ilike("title", `%${q}%`);
  // @lab decoy or-inject cwe=CWE-943 :: string konstan
  const c = await supabase.from("todos").select("*").or("done.eq.true,priority.gte.3");
  res.json({ a: a.data, b: b.data, c: c.data });
}
