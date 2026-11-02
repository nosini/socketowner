import socket,threading,time
def tcp():
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',30443));s.listen()
    while True:
        c,a=s.accept()
        def echo(c):
            with c:
                while data:=c.recv(65536):
                    time.sleep(.2)
                    c.sendall(data)
        threading.Thread(target=echo,args=(c,),daemon=True).start()
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',30553))
    while True:
        d,a=s.recvfrom(65536);s.sendto(d,a)
threading.Thread(target=tcp,daemon=True).start();udp()
