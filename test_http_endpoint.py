"""
Simple test client for the plain HTTP endpoint (not MCP): calls
GET /api/check-rugpull-risk on the live server and completes a real x402
payment automatically using the `requests` library integration.

Much simpler than test_x402_payment.py because this hits a normal REST
endpoint, so the official x402_requests() session wrapper handles the
whole 402 -> pay -> retry flow for us in one line.

SETUP (run once, locally, in a terminal):
    pip install "x402[evm,requests]"

USAGE:
    set TEST_WALLET_PRIVATE_KEY=0x...          (Windows cmd)
    $env:TEST_WALLET_PRIVATE_KEY="0x..."        (PowerShell)
    python test_http_endpoint.py

Reuses the same disposable test wallet as test_x402_payment.py — make sure
it still has a little USDC left on Base (each call here costs $0.01).
"""

import os

from eth_account import Account

from x402 import x402ClientSync
from x402.http.clients import x402_requests
from x402.mechanisms.evm.exact import ExactEvmClientScheme
from x402.mechanisms.evm.signers import EthAccountSigner

SERVER_URL = "https://base-mcp-server.onrender.com/api/check-rugpull-risk"
TEST_ADDRESS_TO_SCREEN = "0xdf1496a7d0fe0fe557d41d2d5ea7e64ac15d032e"


def main() -> None:
    private_key = os.environ.get("TEST_WALLET_PRIVATE_KEY")
    if not private_key:
        raise SystemExit("Set TEST_WALLET_PRIVATE_KEY before running this script.")

    account = Account.from_key(private_key)
    print(f"Using test wallet: {account.address}")

    payment_client = x402ClientSync()
    payment_client.register("eip155:8453", ExactEvmClientScheme(EthAccountSigner(account)))

    session = x402_requests(payment_client)

    print(f"\nCalling {SERVER_URL} ?address={TEST_ADDRESS_TO_SCREEN} ...")
    response = session.get(SERVER_URL, params={"address": TEST_ADDRESS_TO_SCREEN})

    print("\n=== RESULT ===")
    print("Status:", response.status_code)
    print(response.text)


if __name__ == "__main__":
    main()
