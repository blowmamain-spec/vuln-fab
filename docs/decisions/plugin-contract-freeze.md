# Plugin contract 1.0 (frozen)

`vulnfab.plugins.base.CONTRACT_VERSION = "1.0"`. Frozen after the third plugin (Django) was
written; the Supabase, TypeScript and Django plugins all run on it without special cases in the
engine.

## What the contract is

The `StackPlugin` protocol (`docs/spec.md` section 6), the shared IR (`core/models.py`:
`SourceFile`, `ParsedUnit`, `Entrypoint`, `DataAccess`, `SchemaModel`, `Unresolved`, ...), the
rule kinds (`pattern`, `taint`, `schema`, `scanner`, `crosscheck`) and the three optional hooks
`fixture_path`, `attach_drift`, `refine`.

## Core changes that Django needed (all additive)

| Change | Why |
|---|---|
| `Column.references` | foreign keys (owner relations) for model-aware IDOR |
| `ConfigDoc.extras` | settings that are conditional/mutated, so checks can stay quiet |
| `Entrypoint.route/route_file/route_line/traits` | report a view together with its URL |
| `CrosscheckRule.facts: Entrypoint`, `CrosscheckRule.model` | rules over entrypoints; choose which plugin's schema a rule reads (TS rules read Supabase's) |
| `CheckContext.entrypoints` | give check functions the entrypoints |
| optional hook `refine(raw, model)` | Django lowers IDOR confidence for models without an owner relation |
| rule-test `_repo/` directory | extra files that make a stack plugin activate in the fixture repo |
| scanner rules over `html` files | Django templates |
| `unsafe_interpolation` for Python/PHP | f-strings, `%`, `.format`, `"$x"` |
| TIR: `Branch.cond`, `throw`/`raise` -> `Return(None)` | validators in taint rules; early exit |
| taint rules: `guards`, `validators` | tier-B ownership evidence; validation checks |

## Compatibility promise

* Adding a method to the protocol is a **breaking** change (minor version bump). New capabilities
  are added as optional hooks discovered with `getattr`.
* Adding fields with defaults to IR dataclasses is not breaking.
* Removing or renaming anything in the IR or rule schema is breaking and needs a deprecation
  note in `CHANGELOG.md`.
* `tests/unit/test_plugin_contract.py` holds a minimal third-party plugin that exercises every
  rule kind through the public contract only; it must keep passing.
