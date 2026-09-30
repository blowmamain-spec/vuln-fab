res.cookie('sid', token, { httpOnly: true, secure: true });
app.use(session({ secret: s, cookie: { secure: true, httpOnly: true } }));
