app.use(cors({ origin: true, credentials: true })); // vuln: js-cors-wildcard-credentials
app.use(cors({ credentials: true, origin: '*' })); // vuln: js-cors-wildcard-credentials
