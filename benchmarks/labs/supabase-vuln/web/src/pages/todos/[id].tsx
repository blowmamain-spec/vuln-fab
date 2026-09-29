import { supabase } from "../../lib/supabase";

export async function getServerSideProps({ params }: { params: { id: string } }) {
  // @lab decoy idor-eq-id cwe=CWE-639 tier=B :: policy RLS membatasi ke pemilik
  const { data } = await supabase.from("todos").select("*").eq("id", params.id).single();
  return { props: { data } };
}
