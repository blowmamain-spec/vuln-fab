# S3: parsing template (Django, Blade)

**Keputusan: GO dengan tokenizer regex terbatas**; tidak perlu grammar penuh untuk cakupan Fase 6/7.

Prototipe: [`s3_templates_proto.py`](s3_templates_proto.py), 15/15 kasus.

## Pendekatan
- **Django**: tokenizer untuk `{{ … }}`, `{% … %}`, `{# … #}`. Output tidak aman bila ada filter `|safe` (toleran spasi, tidak cocok dengan `|safeish`) atau berada di dalam `{% autoescape off %} … {% endautoescape %}`. Komentar `{# #}` diabaikan.
- **Blade**: `{!! … !!}` = output mentah (temuan). `{{-- … --}}`, `@{{ … }}` (escape literal), `@verbatim … @endverbatim`, dan isi `@php … @endphp` diabaikan (regex tidak menghasilkan `raw` di sana).
- Nomor baris dihitung dari offset, cukup untuk file:line temuan.

## Batasan yang diterima (dicatat di Coverage & limitations)
- Ekspresi di dalam `{{ … }}` tidak diparse sebagai bahasa host di Fase 6/7 awal; taint dari konteks view ke template dilakukan lewat nama variabel (opsional, WP lanjutan).
- Tag kustom (`{% load %}` pustaka pihak ketiga) yang mengubah escaping tidak dimodelkan.
- `@php(...)` inline dan directive kustom Blade tidak dimodelkan.
