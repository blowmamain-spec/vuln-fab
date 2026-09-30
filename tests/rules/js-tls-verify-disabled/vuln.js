const agent = new https.Agent({ rejectUnauthorized: false }); // vuln: js-tls-verify-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // vuln: js-tls-verify-disabled
