// @lab vuln secret-hardcoded cwe=CWE-798 tier=A :: secret literal (palsu)
const PAYMENT_API_SECRET = "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a";

// @lab decoy secret-hardcoded cwe=CWE-798 :: URL biasa
const PAYMENT_API_URL = "https://api.example.com/v1";

// @lab decoy secret-hardcoded cwe=CWE-798 :: placeholder
const placeholderKey = "your-api-key-here";

// @lab decoy secret-hardcoded cwe=CWE-798 :: dibaca dari environment
const fromEnv = process.env.PAYMENT_API_SECRET;

export async function charge(amountCents: number): Promise<Response> {
  return fetch(`${PAYMENT_API_URL}/charge`, {
    method: "POST",
    headers: { Authorization: `Bearer ${PAYMENT_API_SECRET ?? fromEnv ?? placeholderKey}` },
    body: JSON.stringify({ amountCents }),
  });
}
