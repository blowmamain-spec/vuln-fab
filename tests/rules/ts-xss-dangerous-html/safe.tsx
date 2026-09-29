export function A() {
  return <div dangerouslySetInnerHTML={{ __html: "<b>Welcome</b>" }} />;
}

export function B({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function C({ html }: { html: string }) {
  return <div>{html}</div>;
}

export function D({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />;
}
