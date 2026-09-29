export class C {
  constructor(private sanitizer: any) {}

  show(q: string) {
    this.value = this.sanitizer.bypassSecurityTrustHtml(q) // vuln: js-xss
  }

  link(u: string) {
    return this.sanitizer.bypassSecurityTrustUrl(u) // vuln: js-xss
  }
}
