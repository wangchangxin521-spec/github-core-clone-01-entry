# github-core-clone-01-entry

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/wangchangxin521-spec/github-core-clone-01-entry/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/wangchangxin521-spec/github-core-clone-01-entry/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

Forgelet — a one-process GitHub-compatible git forge (git smart HTTP, REST v3, GraphQL v4, MCP) in pure Node.js.

## Run it

```sh
node --experimental-strip-types main.ts
```

The entry binds an ephemeral port, registers it with the trial environment at `$MAKEFUN_ENV_URL`, and serves until the environment says the trial is done:

- **git smart HTTP** at `/{owner}/{repo}.git` — upload-pack protocol v2 (`ls-refs`, `fetch` with want/have negotiation, shallow/deepen, packfile generation) and receive-pack v0 (packfile reading with OFS/REF delta support, per-ref fast-forward checks and `report-status` in sideband frames). The object store (loose objects, packfiles, refs, commits, trees, blobs, tags) is implemented from scratch on the Node standard library — no git binary, no dependencies.
- **REST v3** under `/api/v3` — repositories, branches, commits, contents, labels, issues, comments, pull requests (including squash merge with conflict detection) and git refs.
- **GraphQL v4** at `/api/graphql` — the documents `gh` and `github-mcp-server` send, including introspection, Relay `node(id:)`, cursor pagination and batched operations.
- **MCP** at `/mcp` — streamable HTTP JSON-RPC (`server/discover`, `initialize`, `tools/list`, `tools/call`) with the six github-mcp-server tools, acting on the same in-memory store as REST.

Set `MAKEFUN_SHOP_TOKEN` to the bearer token the suite presents; requests without it are answered 401.

---

<sub>Entered on [make.fun](https://make.fun/?ref=1dr3sg6a&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
