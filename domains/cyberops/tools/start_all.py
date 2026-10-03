"""Start all 16 CyberOps tool servers."""

import argparse
import asyncio
import sys
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent.parent.parent.parent))

from mcp_servers.server_registry import ServerRegistry
from logging_utils import ExperimentLogger


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-port", type=int, default=9000,
                         help="First port for tool servers; allocator "
                              "assigns base_port, base_port+1, ...")
    args = parser.parse_args()

    logger = ExperimentLogger(eval_name="tools", domain="cyberops", config="agenticcyops")
    registry = ServerRegistry(domain="cyberops", logger=logger)
    await registry.start_all(base_port=args.base_port)

    print("\nCyberOps tools started:")
    for tool_id, port in registry.list_tools().items():
        print(f"  {tool_id}: http://127.0.0.1:{port}")

    print("\nPress Ctrl+C to stop all.")
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        await registry.stop_all()


if __name__ == "__main__":
    asyncio.run(main())
