import socket,struct,pathlib
print('\n'.join(x for x in pathlib.Path('/proc/self/status').read_text().splitlines() if x.startswith('Cap')))
s=socket.socket()
try:
 s.setsockopt(0x52534953,1,struct.pack('I',0x12345678))
 print('custom setsockopt OK')
except OSError as e:print('custom setsockopt ERROR',e.errno,str(e))
try:
 s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,123)
 print('SO_MARK unexpectedly OK')
except OSError as e:print('SO_MARK ERROR',e.errno,str(e))
