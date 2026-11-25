#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// PROBE_HOST may be IPv4 or IPv6; the default is IPv4 loopback.
static int addr(unsigned short port, struct sockaddr_storage *s) {
    const char *host=getenv("PROBE_HOST"); char text[64]; int n=sizeof(*s);
    memset(s,0,sizeof(*s)); snprintf(text,sizeof(text),"%s",host?host:"127.0.0.1");
    int family=strchr(text,':')?AF_INET6:AF_INET;
    if(WSAStringToAddressA(text,family,NULL,(struct sockaddr*)s,&n)){printf("bad PROBE_HOST\n");exit(2);}
    if(family==AF_INET6){((struct sockaddr_in6*)s)->sin6_port=htons(port);return sizeof(struct sockaddr_in6);}
    ((struct sockaddr_in*)s)->sin_port=htons(port);return sizeof(struct sockaddr_in);
}
int main(void) {
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    printf("Windows PID=%lu\n",GetCurrentProcessId());fflush(stdout);
    struct sockaddr_storage a,u;int al=addr(30443,&a),ul=addr(30553,&u);int family=a.ss_family;
    SOCKET s=socket(family,SOCK_STREAM,IPPROTO_TCP);
    printf("TCP connect=%d\n",connect(s,(struct sockaddr*)&a,al));fflush(stdout);
    send(s,"tcp-sync",8,0);char b[64];printf("TCP recv=%d\n",recv(s,b,sizeof(b),0));
    WSABUF wb={9,"tcp-async"};DWORD n=0;WSAOVERLAPPED ov={0};ov.hEvent=WSACreateEvent();
    int r=WSASend(s,&wb,1,&n,0,&ov,NULL);
    printf("WSASend=%d error=%d\n",r,WSAGetLastError());
    if(r==SOCKET_ERROR && WSAGetLastError()==WSA_IO_PENDING) WSAGetOverlappedResult(s,&ov,&n,TRUE,&(DWORD){0});
    WSAOVERLAPPED rv={0};rv.hEvent=WSACreateEvent();wb.buf=b;wb.len=sizeof(b);DWORD flags=0;
    r=WSARecv(s,&wb,1,&n,&flags,&rv,NULL);
    printf("WSARecv=%d error=%d\n",r,WSAGetLastError());
    if(r==SOCKET_ERROR && WSAGetLastError()==WSA_IO_PENDING) WSAGetOverlappedResult(s,&rv,&n,TRUE,&flags);
    printf("WSARecv bytes=%lu\n",n);closesocket(s);
    s=socket(family,SOCK_STREAM,IPPROTO_TCP);
    struct sockaddr_storage local;int ll=addr(0,&local);
    if(getenv("PROBE_HOST")){
        // Bind to the wildcard of the probe's family.
        if(family==AF_INET6)memset(&((struct sockaddr_in6*)&local)->sin6_addr,0,16);
        else((struct sockaddr_in*)&local)->sin_addr.s_addr=INADDR_ANY;
    }
    bind(s,(struct sockaddr*)&local,ll);
    GUID guid=WSAID_CONNECTEX;LPFN_CONNECTEX cx;DWORD size;
    WSAIoctl(s,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),&cx,sizeof(cx),&size,NULL,NULL);
    WSAOVERLAPPED cv={0};cv.hEvent=WSACreateEvent();
    BOOL cr=cx(s,(struct sockaddr*)&a,al,"connectex-data",14,&n,&cv);
    printf("ConnectEx=%d error=%d\n",cr,WSAGetLastError());
    if(!cr && WSAGetLastError()==WSA_IO_PENDING) WSAGetOverlappedResult(s,&cv,&n,TRUE,&flags);
    setsockopt(s,SOL_SOCKET,SO_UPDATE_CONNECT_CONTEXT,NULL,0);
    printf("ConnectEx recv=%d\n",recv(s,b,sizeof(b),0));closesocket(s);
    SOCKET d=socket(family,SOCK_DGRAM,IPPROTO_UDP);
    sendto(d,"udp-sendto",10,0,(struct sockaddr*)&u,ul);recv(d,b,sizeof(b),0);
    printf("UDP connect=%d\n",connect(d,(struct sockaddr*)&u,ul));
    send(d,"udp-connected",13,0);recv(d,b,sizeof(b),0);closesocket(d);
    fflush(stdout);WSACleanup();
    // Lets a test inspect the process before it exits.
    if(getenv("PROBE_LINGER"))Sleep(atoi(getenv("PROBE_LINGER")));
    return 0;
}
