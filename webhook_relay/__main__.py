import argparse
import json
import os
import time

from .api import make_server
from .delivery import run_once
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="SQLite-backed webhook delivery exercise")
    parser.add_argument("--db", default="relay.sqlite3")
    parser.add_argument("--allow-loopback", action="store_true",
                        help="Allow HTTP(S) to loopback addresses for local tests")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    worker = commands.add_parser("worker")
    worker.add_argument("--once", action="store_true")
    args = parser.parse_args()
    store = Store(args.db)
    try:
        if args.command == "serve":
            token = os.environ.get("WEBHOOK_API_TOKEN", "")
            if len(token.encode("utf-8")) < 24:
                parser.error("Set WEBHOOK_API_TOKEN to at least 24 bytes")
            with make_server((args.host, args.port), store, token,
                             allow_loopback=args.allow_loopback) as server:
                print(f"Listening on {args.host}:{args.port}", flush=True)
                server.serve_forever()
        else:
            secret = os.environ.get("WEBHOOK_SIGNING_SECRET", "").encode("utf-8")
            if len(secret) < 32:
                parser.error("Set WEBHOOK_SIGNING_SECRET to at least 32 bytes")
            while True:
                result = run_once(store, secret, allow_loopback=args.allow_loopback)
                if result is not None:
                    print(json.dumps(result), flush=True)
                if args.once:
                    return
                if result is None:
                    time.sleep(1)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
