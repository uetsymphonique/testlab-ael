#!/usr/bin/env python3
# Reference implementation for Step 2 (Protocol Tunneling): local TCP forwarder,
# listens on a non-standard port and relays to a local service (e.g. sshd).
# Rewrite variable/function names and structure before pasting into a live shell —
# reusing this file verbatim defeats the "no static-script signature" premise of Step 2.
import socket
import threading

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2222
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 22

BUF_SIZE = 4096


def relay(src, dst):
    try:
        while True:
            data = src.recv(BUF_SIZE)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            src.shutdown(socket.SHUT_RD)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client_sock):
    try:
        upstream = socket.create_connection((TARGET_HOST, TARGET_PORT))
    except OSError:
        client_sock.close()
        return

    t1 = threading.Thread(target=relay, args=(client_sock, upstream), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client_sock), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_sock.close()
    upstream.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(5)
    print(f"[*] listening on {LISTEN_HOST}:{LISTEN_PORT}, forwarding to {TARGET_HOST}:{TARGET_PORT}")

    try:
        while True:
            client_sock, _ = server.accept()
            threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    main()
