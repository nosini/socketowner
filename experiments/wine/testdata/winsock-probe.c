#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <stdio.h>
#include <stdlib.h>

static struct sockaddr_in addr(unsigned short port) {
    struct sockaddr_in a={0}; const char *host=getenv("PROBE_HOST"); a.sin_family=AF_INET;
    a.sin_addr.s_addr=inet_addr(host?host:"127.0.0.1"); a.sin_port=htons(port);return a;
}
int main(void) {
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    printf("Windows PID=%lu\n",GetCurrentProcessId());fflush(stdout);
    struct sockaddr_in a=addr(30443),u=addr(30553);
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    printf("TCP connect=%d\n",connect(s,(struct sockaddr*)&a,sizeof(a)));fflush(stdout);
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
    s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    struct sockaddr_in local=addr(0);if(getenv("PROBE_HOST"))local.sin_addr.s_addr=INADDR_ANY;bind(s,(struct sockaddr*)&local,sizeof(local));
    GUID guid=WSAID_CONNECTEX;LPFN_CONNECTEX cx;DWORD size;
    WSAIoctl(s,SIO_GET_EXTENSION_FUNCTION_POINTER,&guid,sizeof(guid),&cx,sizeof(cx),&size,NULL,NULL);
    WSAOVERLAPPED cv={0};cv.hEvent=WSACreateEvent();
    BOOL cr=cx(s,(struct sockaddr*)&a,sizeof(a),"connectex-data",14,&n,&cv);
    printf("ConnectEx=%d error=%d\n",cr,WSAGetLastError());
    if(!cr && WSAGetLastError()==WSA_IO_PENDING) WSAGetOverlappedResult(s,&cv,&n,TRUE,&flags);
    setsockopt(s,SOL_SOCKET,SO_UPDATE_CONNECT_CONTEXT,NULL,0);
    printf("ConnectEx recv=%d\n",recv(s,b,sizeof(b),0));closesocket(s);
    SOCKET d=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    sendto(d,"udp-sendto",10,0,(struct sockaddr*)&u,sizeof(u));recv(d,b,sizeof(b),0);
    printf("UDP connect=%d\n",connect(d,(struct sockaddr*)&u,sizeof(u)));
    send(d,"udp-connected",13,0);recv(d,b,sizeof(b),0);closesocket(d);
    fflush(stdout);WSACleanup();return 0;
}
