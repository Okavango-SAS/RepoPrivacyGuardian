# RELEASE NOTES TEMPLATE

Use this template for public tags and packaged releases.

## Summary

- What changed in one short paragraph.

## User-visible changes

- CLI:
- Packaging / install:
- GUI (if relevant):
- Documentation:

## Validation evidence

- `python -m pytest -q`
- `python -m build`
- installed entry point help
- installed module help
- smoke checks executed
- CI matrix relevant to the release

## Upgrade notes

- Any changed defaults:
- Any changed flags or outputs:
- Any migration or operator action required:

## Known limitations at release time

- Still best-effort or intentionally manual-review areas:
- Deferred work that is not a blocker for the release:

## Follow-up candidates

- Small next steps worth considering after the release:
