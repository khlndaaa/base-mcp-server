#!/usr/bin/env python3
"""
Base MCP Server (public template).

Exposes a set of read-only Base blockchain tools over the Model
Context Protocol (MCP), so any MCP-compatible AI agent (Claude
Desktop, Claude Code, or any other MCP client) can check wallets and
contracts on Base directly through natural conversation — no manual
block explorer lookups required.

This server is a distillation of five standalone tools built earlier
in this collection (tx monitor, contract verifier, airdrop checker,
rug-pull warning, approval checker) into one always-available MCP
server, exposing the same well-tested Base data logic as callable
tools instead of scheduled GitHub Actions.

Tools exposed:
  - get_wallet_balance         ETH balance of an address
  - get_wallet_activity        Recent transaction activity + a simple 0-100 activity score
  - get_recent_transactions    Most recent transactions for an address
  - check_contract_verification  Is a contract's source code verified? Proxy? Owner?
  - check_rugpull_risk         Heuristic scam-pattern risk score for a contract
  - check_token_approvals      Active ERC-20/NFT approvals granted by a wallet

All tools are READ-ONLY. This server never asks for or handles a
private key, and cannot send transactions, sign anything, or revoke
approvals — it only reads public Base blockchain data.
"""

import os
import json
from typing import Optional

import requests
from mcp.server.fastmcp import Context, FastMCP
from mcp.types import CallToolResult

from x402.http import HTTPFacilitatorClient
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.mcp import (
    PaymentWrapperConfig,
    ResourceInfo,
    create_payment_wrapper,
)
from x402.mcp.server_async import wrap_fastmcp_tool
from x402.schemas import ResourceConfig
from x402.server import x402ResourceServer

CHAIN_ID = 8453  # Base mainnet
BLOCKSCOUT_URL = "https://api.blockscout.com/v2/api"
BASE_RPC_URL = "https://mainnet.base.org"

API_KEY = os.environ.get("BLOCKSCOUT_API_KEY")

# --- x402 payment config ---------------------------------------------------
# The two most expensive/valuable tools (rug-pull risk and approval scanning
# both do heavy multi-request scanning) are gated behind a small USDC
# micropayment. The four simple lookup tools stay free.
X402_PAY_TO = os.environ.get("X402_PAY_TO")  # your Base Account address
X402_NETWORK = "eip155:8453"  # Base mainnet
CDP_API_KEY_ID = os.environ.get("CDP_API_KEY_ID")
CDP_API_KEY_SECRET = os.environ.get("CDP_API_KEY_SECRET")
X402_ENABLED = bool(X402_PAY_TO and CDP_API_KEY_ID and CDP_API_KEY_SECRET)

if X402_ENABLED:
    try:
        from cdp.x402 import create_facilitator_config

        _facilitator_config = create_facilitator_config(CDP_API_KEY_ID, CDP_API_KEY_SECRET)
        _facilitator_client = HTTPFacilitatorClient(_facilitator_config)
        _resource_server = x402ResourceServer(_facilitator_client)
        _resource_server.register(X402_NETWORK, ExactEvmServerScheme())
        _resource_server.initialize()  # network call to the CDP facilitator
    except Exception as exc:  # noqa: BLE001 - defensive: never let a bad
        # facilitator config/network hiccup take the whole server down.
        print(f"[x402] disabled: facilitator setup failed: {exc}")
        X402_ENABLED = False

if X402_ENABLED:

    def _paid_wrapper(tool_name: str, price: str):
        accepts = _resource_server.build_payment_requirements(
            ResourceConfig(
                scheme="exact",
                network=X402_NETWORK,
                pay_to=X402_PAY_TO,
                price=price,
                extra={"name": "USDC", "version": "2"},
            )
        )
        return create_payment_wrapper(
            _resource_server,
            PaymentWrapperConfig(
                accepts=accepts,
                resource=ResourceInfo(url=f"mcp://tool/{tool_name}"),
            ),
        )

UNLIMITED_THRESHOLD = 2**255
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL_TOPIC = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
ALLOWANCE_SELECTOR = "0xdd62ed3e"
IS_APPROVED_FOR_ALL_SELECTOR = "0xe985e9c5"
OWNER_SELECTOR = "0x8da5cb5b"

SUSPICIOUS_PATTERNS = [
    ("blacklist", 8, "ability to block specific addresses"),
    ("excludefromfee", 6, "selective fees for different addresses"),
    ("settaxfee", 6, "fees can be changed after deployment"),
    ("setfee", 6, "fees can be changed after deployment"),
    ("maxtxamount", 5, "arbitrary transaction/balance limits"),
    ("maxwallet", 5, "arbitrary wallet balance limits"),
    ("antiwhale", 5, "artificial trading restrictions"),
    ("cooldown", 5, "artificial trading restrictions"),
    ("tradingenabled", 6, "trading can be manually toggled on/off"),
    ("opentrading", 6, "trading can be manually toggled on/off"),
    ("pause(", 5, "transfers can be fully halted"),
    ("mint(", 4, "additional token supply can be minted post-deploy"),
    ("selfdestruct", 7, "the contract can be destroyed"),
    ("delegatecall", 5, "logic can be delegated to another contract"),
]

PORT = int(os.environ.get("PORT", "0")) or None

mcp = FastMCP(
    "base-tools",
    instructions=(
        "Read-only tools for inspecting wallets and contracts on the Base "
        "blockchain (chainId 8453). Never asks for or uses a private key. "
        "check_rugpull_risk and check_token_approvals require a small USDC "
        "payment on Base via x402; the other four tools are free."
    ),
    host="0.0.0.0" if PORT else "127.0.0.1",
    port=PORT or 8000,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _require_api_key():
    if not API_KEY:
        raise RuntimeError(
            "BLOCKSCOUT_API_KEY environment variable is not set. "
            "Get a free key at https://dev.blockscout.com/ and set it in "
            "your MCP client's server config."
        )


def _api_get(params, retries=2):
    _require_api_key()
    query = {"chainid": CHAIN_ID, "apikey": API_KEY, **params}
    for attempt in range(retries + 1):
        try:
            resp = requests.get(BLOCKSCOUT_URL, params=query, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "0" and data.get("message") not in ("No transactions found", "OK"):
                return None
            return data.get("result")
        except requests.exceptions.RequestException:
            if attempt < retries:
                continue
            return None


def _rpc_call(to, data):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }
    try:
        resp = requests.post(BASE_RPC_URL, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()
    except (requests.exceptions.RequestException, ValueError):
        return None
    if "error" in result:
        return None
    return result.get("result")


def _pad_address(address):
    return "0x" + address.lower().replace("0x", "").zfill(64)


def _fetch_logs(topic0, owner):
    all_logs = []
    page = 1
    offset = 1000
    while page <= 10:
        result = _api_get({
            "module": "logs",
            "action": "getLogs",
            "fromBlock": 0,
            "toBlock": "latest",
            "topic0": topic0,
            "topic1": _pad_address(owner),
            "topic0_1_opr": "and",
            "page": page,
            "offset": offset,
        })
        if not isinstance(result, list) or not result:
            break
        all_logs.extend(result)
        if len(result) < offset:
            break
        page += 1
    return all_logs


def _extract_pairs(logs):
    pairs = set()
    for log in logs:
        contract = log.get("address", "").lower()
        topics = log.get("topics", [])
        if not contract or len(topics) < 3:
            continue
        counterparty = ("0x" + topics[2][-40:]).lower()
        pairs.add((contract, counterparty))
    return pairs


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_wallet_balance(address: str) -> str:
    """Get the native ETH balance of a wallet or contract address on Base.

    Args:
        address: The 0x-prefixed address to check.
    """
    result = _api_get({"module": "account", "action": "balance", "address": address})
    try:
        balance = int(result) / 1e18
    except (TypeError, ValueError):
        return f"Could not fetch balance for {address}. The API may be temporarily unavailable."
    return f"{address} has a balance of {balance:.6f} ETH on Base."


@mcp.tool()
def get_recent_transactions(address: str, limit: int = 10) -> str:
    """Get the most recent transactions for an address on Base.

    Args:
        address: The 0x-prefixed address to check.
        limit: Maximum number of recent transactions to return (default 10, max 50).
    """
    limit = max(1, min(limit, 50))
    result = _api_get({
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": limit,
        "sort": "desc",
    })
    if not isinstance(result, list) or not result:
        return f"No transactions found for {address} on Base."

    lines = [f"Most recent {len(result)} transaction(s) for {address}:"]
    for tx in result:
        direction = "OUT" if tx.get("from", "").lower() == address.lower() else "IN"
        value_eth = int(tx.get("value", "0")) / 1e18
        status = "OK" if tx.get("isError", "0") == "0" else "FAILED"
        lines.append(
            f"- [{direction}] {value_eth:.6f} ETH | block {tx.get('blockNumber')} | "
            f"hash {tx.get('hash')} | {status}"
        )
    return "\n".join(lines)


@mcp.tool()
def get_wallet_activity(address: str) -> str:
    """Compute a rough 0-100 on-chain activity score for a wallet on Base.

    Based on transaction count, number of unique active days, contract
    diversity, and wallet age (all sampled from the most recent 1,000
    transactions). This is a heuristic indicator, not an official
    metric of any airdrop or program.

    Args:
        address: The 0x-prefixed wallet address to check.
    """
    txs = _api_get({
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "page": 1,
        "offset": 1000,
        "sort": "asc",
    })
    if not isinstance(txs, list) or not txs:
        return f"{address} has no transaction history on Base, or it could not be fetched."

    balance_result = _api_get({"module": "account", "action": "balance", "address": address})
    try:
        balance_eth = int(balance_result) / 1e18
    except (TypeError, ValueError):
        balance_eth = 0.0

    timestamps = sorted(int(tx["timeStamp"]) for tx in txs if tx.get("timeStamp"))
    tx_count = len(txs)
    active_days = len({ts // 86400 for ts in timestamps})
    wallet_age_days = max(1, (timestamps[-1] - timestamps[0]) // 86400) if timestamps else 0
    unique_contacts = len({tx.get("to", "").lower() for tx in txs if tx.get("to")})

    score = 0
    score += min(30, tx_count)
    score += min(25, active_days * 2)
    score += min(20, unique_contacts)
    score += min(15, wallet_age_days // 10)
    score += 10 if balance_eth > 0 else 0
    score = min(100, score)

    sample_note = " (sampled from the most recent 1,000 transactions)" if tx_count >= 1000 else ""

    return (
        f"Activity score for {address}: {score}/100{sample_note}\n"
        f"- Transactions: {tx_count}\n"
        f"- Unique active days: {active_days}\n"
        f"- Unique contacts/contracts: {unique_contacts}\n"
        f"- Wallet age: {wallet_age_days} days\n"
        f"- Current balance: {balance_eth:.6f} ETH"
    )


@mcp.tool()
def check_contract_verification(address: str) -> str:
    """Check whether a contract on Base has verified source code, and basic metadata.

    Reports source verification status, whether it's an upgradeable
    proxy, and whether ownership has been renounced (for contracts
    following the standard Ownable pattern).

    Args:
        address: The 0x-prefixed contract address to check.
    """
    data = _api_get({"module": "contract", "action": "getsourcecode", "address": address})
    contract = data[0] if isinstance(data, list) and data else None

    if not contract or not contract.get("SourceCode"):
        return f"{address}: source code is NOT verified. Its logic cannot be inspected directly."

    is_proxy = contract.get("Proxy") == "1"
    compiler = contract.get("CompilerVersion", "unknown")

    owner_data = _rpc_call(address, OWNER_SELECTOR)
    if owner_data and owner_data not in ("0x", "0x0"):
        owner_addr = "0x" + owner_data[-40:]
        burn_addresses = {
            "0x0000000000000000000000000000000000000000",
            "0x000000000000000000000000000000000000dead",
        }
        owner_status = "renounced" if owner_addr.lower() in burn_addresses else f"active ({owner_addr})"
    else:
        owner_status = "no owner() function found, or contract isn't Ownable"

    return (
        f"{address}: source code IS verified (compiler {compiler}).\n"
        f"- Proxy/upgradeable: {'yes' if is_proxy else 'no'}\n"
        f"- Owner: {owner_status}"
    )


def _check_rugpull_risk_impl(address: str) -> str:
    data = _api_get({"module": "contract", "action": "getsourcecode", "address": address})
    contract = data[0] if isinstance(data, list) and data else None

    if not contract or not contract.get("SourceCode"):
        return (
            f"{address}: source code is NOT verified — risk score 40/100 (MEDIUM RISK). "
            f"Contract logic cannot be inspected directly. This alone is a caution signal."
        )

    is_proxy = contract.get("Proxy") == "1"
    source = contract["SourceCode"].lower()

    findings = []
    pattern_score = 0
    for pattern, weight, description in SUSPICIOUS_PATTERNS:
        if pattern in source:
            findings.append(f"{pattern.rstrip('(')} (+{weight}): {description}")
            pattern_score += weight
    pattern_score = min(30, pattern_score)

    score = pattern_score
    if is_proxy:
        score += 10

    owner_data = _rpc_call(address, OWNER_SELECTOR)
    owner_line = "no owner() function found, or contract isn't Ownable"
    if owner_data and owner_data not in ("0x", "0x0"):
        owner_addr = "0x" + owner_data[-40:]
        burn_addresses = {
            "0x0000000000000000000000000000000000000000",
            "0x000000000000000000000000000000000000dead",
        }
        if owner_addr.lower() in burn_addresses:
            owner_line = "renounced"
        else:
            owner_line = f"active ({owner_addr})"
            score += 20

    score = min(100, score)
    if score >= 70:
        label = "HIGH RISK"
    elif score >= 40:
        label = "MEDIUM RISK"
    elif score >= 15:
        label = "LOW RISK"
    else:
        label = "NO SIGNALS FOUND"

    lines = [
        f"{address}: risk score {score}/100 ({label})",
        f"- Source verified: yes",
        f"- Proxy/upgradeable: {'yes' if is_proxy else 'no'}",
        f"- Owner: {owner_line}",
    ]
    if findings:
        lines.append(f"- Suspicious patterns found ({len(findings)}):")
        lines.extend(f"  - {f}" for f in findings)
    else:
        lines.append("- No suspicious code patterns found")
    lines.append("Note: heuristic screening only, not a security audit.")
    return "\n".join(lines)


def _check_token_approvals_impl(address: str) -> str:
    approval_logs = _fetch_logs(APPROVAL_TOPIC, address)
    approval_for_all_logs = _fetch_logs(APPROVAL_FOR_ALL_TOPIC, address)

    erc20_pairs = _extract_pairs(approval_logs)
    nft_pairs = _extract_pairs(approval_for_all_logs)

    lines = [f"Active approvals for {address}:"]
    active_count = 0
    high_risk_count = 0

    for token, spender in sorted(erc20_pairs):
        data = ALLOWANCE_SELECTOR + _pad_address(address)[2:] + _pad_address(spender)[2:]
        raw = _rpc_call(token, data)
        if not raw or raw in ("0x", "0x0"):
            continue
        try:
            allowance = int(raw, 16)
        except ValueError:
            continue
        if not allowance:
            continue
        active_count += 1
        if allowance >= UNLIMITED_THRESHOLD:
            high_risk_count += 1
            lines.append(f"- [UNLIMITED] token {token} -> spender {spender}")
        else:
            lines.append(f"- [limited: {allowance}] token {token} -> spender {spender}")

    for collection, operator in sorted(nft_pairs):
        data = IS_APPROVED_FOR_ALL_SELECTOR + _pad_address(address)[2:] + _pad_address(operator)[2:]
        raw = _rpc_call(collection, data)
        if raw is None:
            continue
        try:
            is_approved = int(raw, 16) != 0
        except ValueError:
            continue
        if not is_approved:
            continue
        active_count += 1
        high_risk_count += 1
        lines.append(f"- [FULL COLLECTION] {collection} -> operator {operator}")

    if active_count == 0:
        return f"{address} has no active token approvals on Base."

    lines.append(f"\nTotal: {active_count} active approval(s), {high_risk_count} high-risk/unlimited.")
    lines.append("To revoke, use https://revoke.cash or Basescan/Blockscout's Token Approvals page.")
    return "\n".join(lines)


RUGPULL_DOC = (
    "Run a heuristic rug-pull risk screen on a Base contract. Checks source "
    "verification, common scam-token code patterns, ownership status, and "
    "proxy/upgradeability. Returns a 0-100 risk score. Heuristic only, NOT a "
    "security audit."
)
APPROVALS_DOC = (
    "Check a wallet's active ERC-20 and NFT token approvals on Base. Scans "
    "historical Approval/ApprovalForAll events and verifies current on-chain "
    "state. READ-ONLY, cannot revoke anything."
)

if X402_ENABLED:
    from x402.mcp import MCPToolResult

    _paid_rugpull = _paid_wrapper("check_rugpull_risk", "$0.01")
    _paid_approvals = _paid_wrapper("check_token_approvals", "$0.02")

    async def _rugpull_handler(args, _ctx):
        return MCPToolResult(
            content=[{"type": "text", "text": _check_rugpull_risk_impl(args["address"])}]
        )

    async def _approvals_handler(args, _ctx):
        return MCPToolResult(
            content=[{"type": "text", "text": _check_token_approvals_impl(args["address"])}]
        )

    _rugpull_tool = wrap_fastmcp_tool(_paid_rugpull, _rugpull_handler, tool_name="check_rugpull_risk")
    _approvals_tool = wrap_fastmcp_tool(
        _paid_approvals, _approvals_handler, tool_name="check_token_approvals"
    )

    @mcp.tool()
    async def check_rugpull_risk(address: str, ctx: Context) -> CallToolResult:
        f"""{RUGPULL_DOC} Requires payment of $0.01 USDC on Base."""
        return await _rugpull_tool({"address": address}, ctx)

    @mcp.tool()
    async def check_token_approvals(address: str, ctx: Context) -> CallToolResult:
        f"""{APPROVALS_DOC} Requires payment of $0.02 USDC on Base."""
        return await _approvals_tool({"address": address}, ctx)

else:
    @mcp.tool()
    def check_rugpull_risk(address: str) -> str:
        f"""{RUGPULL_DOC}

        Args:
            address: The 0x-prefixed contract address to screen.
        """
        return _check_rugpull_risk_impl(address)

    @mcp.tool()
    def check_token_approvals(address: str) -> str:
        f"""{APPROVALS_DOC}

        Args:
            address: The 0x-prefixed wallet address to check.
        """
        return _check_token_approvals_impl(address)


def main():
    # HTTP/SSE transport is required for x402 (and for public/hosted access
    # in general) — stdio only works for a locally-running client like
    # Claude Desktop. Falls back to stdio if PORT isn't set, so local dev
    # via Claude Desktop config still works unchanged.
    if os.environ.get("PORT"):
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
