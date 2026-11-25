"""SOCKS5 servers which echo instead of connecting, one per tag.

Port BASE+i answers as tag Ln for n = i, zero-padded to three digits. Each
connection's first four bytes are the sender's tag; one line per connection,
"expected received", shows whether the proxy chosen for it was the sender's.
"""
import socket, sys, threading

host, base, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
lock = threading.Lock()


def exact(c, n):
    data = b''
    while len(data) < n:
        chunk = c.recv(n - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


def serve(c, tag):
    with c:
        try:
            _, methods = exact(c, 2)
            exact(c, methods)
            c.sendall(b'\x05\x00')
            _, command, _, kind = exact(c, 4)
            exact(c, {1: 4, 4: 16}.get(kind) or exact(c, 1)[0])
            exact(c, 2)
            if command != 1:
                return
            c.sendall(b'\x05\x00\x00\x01' + bytes(6))
            received = exact(c, 4)
            with lock:
                print(tag, received.decode(errors='replace'), flush=True)
            c.sendall(received)
            while c.recv(65536):
                pass
        except (EOFError, OSError):
            pass


def listen(i):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, base + i))
    s.listen(1024)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c, f'L{i:03d}'), daemon=True).start()


threads = [threading.Thread(target=listen, args=(i,), daemon=True) for i in range(count)]
for t in threads:
    t.start()
for t in threads:
    t.join()
