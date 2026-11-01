import socket,struct,pathlib
print('\n'.join(x for x in pathlib.Path('/proc/self/status').read_text().splitlines() if x.startswith(('Cap','NSpid'))))
for family in [socket.AF_INET,socket.AF_INET6]:
 for level,opt,value,label in [(socket.SOL_SOCKET,socket.SO_MARK,123,'SO_MARK'),
      (socket.IPPROTO_IP,socket.IP_TOS,0x28,'IP_TOS'),
      (socket.IPPROTO_IPV6,socket.IPV6_TCLASS,0x28,'IPV6_TCLASS'),
      (socket.IPPROTO_IP,51,struct.pack('I',(45199<<16)|45100),'IP_LOCAL_PORT_RANGE')]:
  if family==socket.AF_INET and label=='IPV6_TCLASS' or family==socket.AF_INET6 and label in ['IP_TOS','IP_LOCAL_PORT_RANGE']:continue
  s=socket.socket(family,socket.SOCK_STREAM)
  try:
   s.setsockopt(level,opt,value)
   if label=='IP_LOCAL_PORT_RANGE':s.bind(('0.0.0.0',0));print(family,label,'OK bound',s.getsockname())
   else:print(family,label,'OK',s.getsockopt(level,opt))
  except OSError as e:print(family,label,'ERROR',e.errno,str(e))
  s.close()
