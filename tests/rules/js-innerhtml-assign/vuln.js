el.innerHTML = `<b>${user}</b>`; // vuln: js-innerhtml-assign
el.innerHTML += "<b>" + name + "</b>"; // vuln: js-innerhtml-assign
row.innerHTML = `<td>${escapeHtml(a)}</td><td>${b}</td>`; // vuln: js-innerhtml-assign
document.body.outerHTML = "<p>" + html + "</p>"; // vuln: js-innerhtml-assign
