import { createClient } from "npm:@supabase/supabase-js@2";

Deno.serve(async (req: Request) => {
  const payload = await req.json();
  // @lab decoy service-role-client cwe=CWE-522 lines=4 :: kunci service_role dipakai di server (edge function)
  const admin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  );
  // @lab decoy table-no-rls cwe=CWE-862 lines=1 :: klien service_role melewati RLS; bukan masalah RLS
  await admin.from("audit_log").insert({ actor: "legacy-hook", action: String(payload.action) });
  return new Response("ok");
});
