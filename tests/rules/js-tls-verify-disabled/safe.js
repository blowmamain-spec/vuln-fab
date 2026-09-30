const agent = new https.Agent({ rejectUnauthorized: true });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
