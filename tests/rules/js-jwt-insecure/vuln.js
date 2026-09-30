jwt.verify(token, key, { algorithms: ['none'] }); // vuln: js-jwt-insecure
jwt.verify(token, key, { ignoreExpiration: true }); // vuln: js-jwt-insecure
