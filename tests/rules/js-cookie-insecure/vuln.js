res.cookie('sid', token, { httpOnly: false, path: '/' }); // vuln: js-cookie-insecure
res.cookie('sid', token, { secure: false }); // vuln: js-cookie-insecure
app.use(session({ secret: s, cookie: { secure: false } })); // vuln: js-cookie-insecure
