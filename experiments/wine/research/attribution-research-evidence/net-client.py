import socket, struct, time, json
import sys, pathlib
sys.stdout=open(pathlib.Path(__file__).with_name('inner.jsonl'),'w',buffering=1)
sockets = []
for kind, port, dest in [(socket.SOCK_STREAM, 41234, ('1.1.1.1',443)),
                          (socket.SOCK_STREAM, 58830, ('1.1.1.1',443)),
                          (socket.SOCK_DGRAM, 41234, ('1.1.1.1',53)),
                          (socket.SOCK_DGRAM, 58830, ('1.1.1.1',53))]:
    s=socket.socket(socket.AF_INET,kind);s.settimeout(5);s.bind(('0.0.0.0',port))
    try:
        s.connect(dest)
        result = 'connected'
        if kind == socket.SOCK_DGRAM:
            s.send(bytes.fromhex('123401000001000000000000')+b'\x07example\x03com\x00'+struct.pack('!HH',1,1))
            try: result = 'DNS reply bytes='+str(len(s.recv(4096)))
            except OSError as e: result = repr(e)
        print(json.dumps(dict(kind=kind,inner=s.getsockname(),dest=dest,result=result)),flush=True)
    except OSError as e: print(json.dumps(dict(kind=kind,inner=s.getsockname(),error=repr(e))),flush=True)
    sockets.append(s)
time.sleep(12)
