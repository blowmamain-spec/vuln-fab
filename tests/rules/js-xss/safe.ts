export class C {
  constructor(private sanitizer: any) {}

  show() {
    this.value = this.sanitizer.bypassSecurityTrustHtml('<b>static</b>')
    return this.sanitizer.sanitize(1, this.userValue)
  }
}
