# -*- coding: utf-8 -*-
"""
Демо-сервер для разработки интерфейса без KVM: имитирует службы, порты и логи.

    python3 tests/demo_server.py [--port 8999] [--tls]
Пароль root в демо: S3cret!pass
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from helpers import ServerFixture  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--stopped", default="kaspersky-vm-worker.service")
    args = parser.parse_args()
    srv = ServerFixture(tls=args.tls, restart_delay=2.5, settle=1.0)
    if args.stopped:
        srv.fake.stop(args.stopped, failed=True)
    print("Demo: %s  (root password: %s)" % (srv.base, ServerFixture.PASSWORD))
    sys.stdout.flush()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.close()


if __name__ == "__main__":
    main()
