import argparse,socket,threading,time
p=argparse.ArgumentParser()
p.add_argument('host',nargs='?',default='127.0.0.1')
p.add_argument('--tcp',type=int,nargs='*',default=[30443])
p.add_argument('--udp',type=int,nargs='*',default=[30553])
p.add_argument('--delay',type=float,default=.2,help='seconds before each TCP echo')
a=p.parse_args()
family=socket.AF_INET6 if ':' in a.host else socket.AF_INET
def tcp(port):
    s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((a.host,port));s.listen(1024)
    while True:
        c,_=s.accept()
        def echo(c):
            with c:
                while data:=c.recv(65536):
                    time.sleep(a.delay)
                    c.sendall(data)
        threading.Thread(target=echo,args=(c,),daemon=True).start()
def udp(port):
    s=socket.socket(family,socket.SOCK_DGRAM);s.bind((a.host,port))
    while True:
        d,peer=s.recvfrom(65536);s.sendto(d,peer)
threads=[threading.Thread(target=tcp,args=(port,),daemon=True) for port in a.tcp]
threads+=[threading.Thread(target=udp,args=(port,),daemon=True) for port in a.udp]
for t in threads:t.start()
for t in threads:t.join()
