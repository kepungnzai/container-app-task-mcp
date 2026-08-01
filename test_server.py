#!/usr/bin/env python
"""MCP Client script for testing the mcp-hello-cimd server over Streamable HTTP.

Run the server first:

    uvicorn mcp_hello_cimd.main:app --port 8001

Then run this client:

    python streamable_http_client.py
"""

import argparse
import asyncio
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def run_client(url: str) -> None:
    print(f"Connecting to MCP server at {url}...")
    try:
        async with streamablehttp_client(url) as (read_stream, write_stream, get_session_id):
            print(f"Session ID: {get_session_id()}")
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize the session
                await session.initialize()
                print("Session initialized successfully.\n")

                # 1. List available tools
                print("=== Listing Tools ===")
                tools_response = await session.list_tools()
                for tool in tools_response.tools:
                    print(f"- {tool.name}: {tool.description}")
                print()

                # 2. Call say_hello tool
                print("=== Testing say_hello ===")
                name = "HTTP Client Tester"
                result = await session.call_tool("say_hello", arguments={"name": name})
                print(f"Arguments: {{'name': '{name}'}}")
                for item in result.content:
                    text = getattr(item, "text", None)
                    print(f"Response: {text if text is not None else item}")
                print()

                # 3. Call cimd_cache_info tool
                print("=== Testing cimd_cache_info ===")
                result = await session.call_tool("cimd_cache_info", arguments={})
                for item in result.content:
                    text = getattr(item, "text", None)
                    print(f"Response: {text if text is not None else item}")
                print()
    except Exception as e:
        print(f"Failed to connect or communicate with the server: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the MCP Streamable HTTP test client."
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8080/mcp",
        help="The Streamable HTTP endpoint URL of the MCP server "
        "(default: http://localhost:8080/mcp)",
    )
    args = parser.parse_args()

    try:
        asyncio.run(run_client(args.url))
    except KeyboardInterrupt:
        print("\nClient terminated by user.")
    except Exception:
        sys.exit(1)