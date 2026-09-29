el.innerHTML = html; // vuln: js-innerhtml-var
el.innerHTML = render(x); // vuln: js-innerhtml-var
el.innerHTML += fragment; // vuln: js-innerhtml-var
