export function A({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />; // vuln: ts-xss-dangerous-html
}

export function B({ post }: { post: { body: string } }) {
  return <p className="x" dangerouslySetInnerHTML={{ __html: post.body }}></p>; // vuln: ts-xss-dangerous-html
}
