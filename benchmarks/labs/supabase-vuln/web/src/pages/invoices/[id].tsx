import { supabase } from "../../lib/supabase";

export async function getServerSideProps({ params, user }: { params: { id: string }; user: { id: string } }) {
  // @lab vuln idor-eq-id cwe=CWE-639 tier=B lines=1 :: fetch by id dari request, policy tidak membatasi pemilik
  const { data } = await supabase.from("invoices").select("*").eq("id", params.id).single();
  // @lab decoy idor-eq-id cwe=CWE-639 tier=B lines=1 :: filter pemilik eksplisit
  const own = await supabase.from("invoices").select("*").eq("id", params.id).eq("user_id", user.id).single();
  return { props: { data, own: own.data } };
}
