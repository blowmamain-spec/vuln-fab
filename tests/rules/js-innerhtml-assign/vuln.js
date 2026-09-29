el.innerHTML = user; // vuln: js-innerhtml-assign
el.innerHTML += "<b>" + name + "</b>"; // vuln: js-innerhtml-assign
document.body.outerHTML = html; // vuln: js-innerhtml-assign
