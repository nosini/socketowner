// Relay load: threads each open short TCP connections and UDP sockets in turn.
// Usage: load-probe TCP-PORT UDP-PORT ROUNDS THREADS TAG, with PROBE_HOST set.
// Each TCP connection sends the four-byte TAG, so whatever answers can tell
// which program sent it. UDP-PORT 0 skips UDP.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct sockaddr_storage tcp_addr, udp_addr;
static int addr_len, rounds, udp;
static char tag[5];
static volatile LONG tcp_ok, tcp_fail, udp_ok, udp_fail;

static int addr(const char *host, unsigned short port, struct sockaddr_storage *s) {
    char text[64]; int n=sizeof(*s), family;
    memset(s,0,sizeof(*s)); snprintf(text,sizeof(text),"%s",host);
    family=strchr(text,':')?AF_INET6:AF_INET;
    if(WSAStringToAddressA(text,family,NULL,(struct sockaddr*)s,&n)) return 0;
    if(family==AF_INET6){((struct sockaddr_in6*)s)->sin6_port=htons(port);return sizeof(struct sockaddr_in6);}
    ((struct sockaddr_in*)s)->sin_port=htons(port);return sizeof(struct sockaddr_in);
}

static DWORD WINAPI worker(void *unused) {
    char b[16]; DWORD timeout=5000, udp_timeout=2000;
    for(int i=0;i<rounds;i++){
        SOCKET s=socket(tcp_addr.ss_family,SOCK_STREAM,IPPROTO_TCP);
        setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
        if(!connect(s,(struct sockaddr*)&tcp_addr,addr_len)&&send(s,tag,4,0)==4&&recv(s,b,sizeof(b),0)==4)
            InterlockedIncrement(&tcp_ok);
        else InterlockedIncrement(&tcp_fail);
        closesocket(s);
        if(!udp) continue;
        SOCKET d=socket(udp_addr.ss_family,SOCK_DGRAM,IPPROTO_UDP);
        setsockopt(d,SOL_SOCKET,SO_RCVTIMEO,(char*)&udp_timeout,sizeof(udp_timeout));
        // A datagram can be dropped under load; retries reuse the socket, and so the flow.
        int ok=0;
        for(int attempt=0;attempt<3&&!ok;attempt++)
            ok=sendto(d,"load",4,0,(struct sockaddr*)&udp_addr,addr_len)==4&&recv(d,b,sizeof(b),0)==4;
        InterlockedIncrement(ok?&udp_ok:&udp_fail);
        closesocket(d);
    }
    return 0;
}

int main(int argc, char **argv) {
    WSADATA w; const char *host=getenv("PROBE_HOST"); int threads;
    if(argc!=6||!host||strlen(argv[5])!=4){printf("usage: load-probe TCP-PORT UDP-PORT ROUNDS THREADS TAG\n");return 2;}
    WSAStartup(MAKEWORD(2,2),&w);
    addr_len=addr(host,atoi(argv[1]),&tcp_addr);
    if(!addr_len||!addr(host,atoi(argv[2]),&udp_addr)){printf("bad PROBE_HOST\n");return 2;}
    rounds=atoi(argv[3]);threads=atoi(argv[4]);udp=atoi(argv[2])!=0;memcpy(tag,argv[5],4);
    printf("Windows PID=%lu\n",GetCurrentProcessId());fflush(stdout);
    HANDLE *h=calloc(threads,sizeof(*h));
    DWORD start=GetTickCount();
    for(int i=0;i<threads;i++)h[i]=CreateThread(NULL,0,worker,NULL,0,NULL);
    for(int i=0;i<threads;i++){WaitForSingleObject(h[i],INFINITE);CloseHandle(h[i]);}
    printf("load tcp_ok=%ld tcp_fail=%ld udp_ok=%ld udp_fail=%ld ms=%lu\n",
           tcp_ok,tcp_fail,udp_ok,udp_fail,GetTickCount()-start);
    fflush(stdout);WSACleanup();return tcp_fail||udp_fail;
}
