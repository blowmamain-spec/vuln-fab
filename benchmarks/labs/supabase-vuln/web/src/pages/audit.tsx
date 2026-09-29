import { supabase } from "../lib/supabase";

export default async function AuditPage() {
  // @lab vuln table-no-rls cwe=CWE-862 tier=A :: klien anon membaca tabel tanpa RLS
  const { data: log } = await supabase.from("audit_log").select("*");
  // @lab decoy table-no-rls cwe=CWE-862 :: tabel ber-RLS
  const { data: todos } = await supabase.from("todos").select("*");
  return (
    <ul>
      {(log ?? []).map((l) => (
        <li key={l.id}>{l.action}</li>
      ))}
      <li>{todos?.length}</li>
    </ul>
  );
}
