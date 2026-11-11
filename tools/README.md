# tools/

Test harnesses. Run from the repository root, with `ts/` built (`cd ts && npm ci && npx tsc`).

| Path | What | Run |
|---|---|---|
| [`sim/`](sim/README.md) | agent swarms, dishonest worlds, keeper chaos | `node tools/sim/swarm.mjs` |
| [`docs-test/`](docs-test/README.md) | word budgets, docs-only comprehension rounds | `node tools/docs-test/check-budgets.mjs` |
| [`demo/`](demo/two-machines.md) | two agents pairing through a relay | `sh tools/demo/two-machines.sh` |
| [`gate/`](gate/README.md) | provenance gate prototype for agent tools | `node tools/gate/claude-code/test.mjs` |
