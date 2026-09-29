import DOMPurify from "dompurify";

type Props = { html: string };

// @lab vuln xss-dangerous-html cwe=CWE-79 tier=A lines=2 :: HTML dari props tanpa sanitasi
export function PostBody({ html }: Props) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// @lab decoy xss-dangerous-html cwe=CWE-79 lines=2 :: disanitasi DOMPurify
export function SafePostBody({ html }: Props) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

// @lab decoy xss-dangerous-html cwe=CWE-79 lines=2 :: string statis
export function Banner() {
  return <div dangerouslySetInnerHTML={{ __html: "<b>Welcome</b>" }} />;
}
