# Agent Instructions and Operational Rules

For automated coding agents maintaining or inspecting this package:

## Installation and Environment
- Do not attempt to run on Node.js versions prior to v20.
- Install dependencies with clean npm invocation:
```bash
npm install
```
- Import from `src/` modules directly; do not import internal build paths.

## Testing Rules
- Execute tests using `node --test tests/maximal-suite.test.mjs`.
- Do not suppress assertion errors with empty catch blocks.
- Do not hardcode expected test outputs; use verified KAT tables.
- Do not mutate imported vector fixtures in place.
- All new KAT implementations must import from `src/` modules.
- Ensure all test cells record output status without silent omission.
