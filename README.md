# Base MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Built for Base](https://img.shields.io/badge/Built%20for-Base-0052FF)](https://base.org)

A read-only [MCP](https://modelcontextprotocol.io) (Model Context
Protocol) server that lets any MCP-compatible AI agent — Claude
Desktop, Claude Code, or any other MCP client — inspect wallets and
contracts on **Base** directly through natural conversation, instead
of manually looking things up on a block explorer.

This server distills five standalone tools from this collection (a
transaction monitor, a contract verifier, an airdrop eligibility
checker, a rug-pull risk scorer, and a token approval checker) into
one always-available set of MCP tools, backed by the same
well-tested Base data logic.

## Tools exposed

| Tool | What it does |
|---|---|
| `get_wallet_balance` | ETH balance of an address |
| `get_recent_transactions` | Most recent transactions for an address |
| `get_wallet_activity` | 0-100 heuristic on-chain activity score |
| `check_contract_verification` | Source verification, proxy status, owner status |
| `check_rugpull_risk` | 0-100 heuristic scam-pattern risk score |
| `check_token_approvals` | Active ERC-20/NFT approvals granted by a wallet |

## ⚠️ This server is read-only

It never asks for or handles a private key, and cannot send
transactions, sign anything, or revoke approvals — every tool only
reads public Base blockchain data (via the Blockscout Pro API and
Base's public RPC node).

## Setup

### 1. Requirements

- Python 3.10+
- A free Blockscout Pro API key: https://dev.blockscout.com/ → Login → create a key

### 2. Install

```bash
git clone https://github.com/YOUR_USER/base-mcp-server.git
cd base-mcp-server
pip install -r requirements.txt
```

### 3. Configure your MCP client

**Claude Desktop** — edit your `claude_desktop_config.json`
(Settings → Developer → Edit Config) and add:

```json
{
  "mcpServers": {
    "base-tools": {
      "command": "python",
      "args": ["/absolute/path/to/base-mcp-server/server.py"],
      "env": {
        "BLOCKSCOUT_API_KEY": "your_key_here"
      }
    }
  }
}
```

**Claude Code** — from the project directory:

```bash
claude mcp add base-tools --env BLOCKSCOUT_API_KEY=your_key_here -- python /absolute/path/to/base-mcp-server/server.py
```

**Any other MCP client** — point it at `python server.py` with
`BLOCKSCOUT_API_KEY` set in its environment; the server speaks
standard MCP over stdio.

Restart your client after editing the config. You should see
`base-tools` (with its 6 tools) show up as an available MCP server.

### 4. Try it

Once connected, just ask your agent things like:

- "What's the ETH balance of 0x...?"
- "Check this Base contract for rug-pull risk: 0x..."
- "Does this wallet have any risky unlimited token approvals?"
- "Is this contract's source code verified on Base?"
- "Show me the last 10 transactions for this address."

The agent will call the relevant tool automatically based on what you ask.

## How it works

- All tools talk to Base (chainId 8453) through the free, Etherscan-compatible
  Blockscout Pro API, plus a couple of direct JSON-RPC calls to Base's
  official public node (`mainnet.base.org`) for on-chain reads like
  `owner()` and `allowance()` that are more reliable done directly
  than through an explorer's compatibility layer.
- Every tool degrades gracefully: if an API call fails, the tool
  returns a clear text message explaining that, instead of crashing
  the whole server or the agent's turn.
- The rug-pull risk score and activity score use the exact same
  heuristics as the standalone [Base Rug Pull Early
  Warning](https://github.com/khlndaaa/base-rugpull-warning) and
  [Base Airdrop Eligibility
  Checker](https://github.com/khlndaaa/base-airdrop-checker-public)
  tools — see those repos for more detail on the scoring logic.

## Limitations

- Heuristic tools (`check_rugpull_risk`, `get_wallet_activity`) are
  **not** a substitute for a real security audit or official program
  criteria — always verify independently before acting on the results.
- Transaction and approval scanning samples up to 1,000 recent events
  for performance; very old activity outside that window won't be
  reflected.
- Depends on the free tiers of the Blockscout Pro API and Base's
  public RPC node; if either is rate-limited or briefly down, the
  affected tool will report that instead of returning data.

## License

MIT — use it, modify it, fork it freely.
