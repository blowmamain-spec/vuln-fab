el.innerHTML = "<b>static</b>";
el.innerHTML = "";
el.textContent = user;
const html = el.innerHTML;
el.innerHTML = `<td>${escapeHtml(a)}</td><td>${esc(b)}</td>`;
el.innerHTML = `<b>${DOMPurify.sanitize(x)}</b>`;
el.innerHTML = `${Number(n)} item, ${items.length} more, ${price.toFixed(2)}`;
el.innerHTML = "<b>" + escapeHtml(name) + "</b>";
el.innerHTML = html;
el.innerHTML = render(x);
el.innerHTML = '<option value="">All</option>' + Object.keys(map).map((k) => `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`).join("");
el.innerHTML = rows.map((r) => {
  const label = r.ok ? "yes" : "no";
  return `<tr><td>${escapeHtml(r.name)}</td><td>${r.count}</td></tr>`;
}).join("");
el.innerHTML = `<p>${note ? escapeHtml(note) : "-"}</p><b>${escapeHtml(title) || ""}</b>`;
el.innerHTML = `${open && `<i>${esc(t)}</i>`}`;
