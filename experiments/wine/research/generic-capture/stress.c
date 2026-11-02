#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <stdio.h>
static volatile LONG ok, failed, lasterr;
static unsigned __stdcall worker(void *a){
    struct sockaddr_in d={0};d.sin_family=AF_INET;d.sin_addr.s_addr=inet_addr("127.0.0.1");d.sin_port=htons(30443);
    struct sockaddr_in u=d;u.sin_port=htons(30553);
    for(int i=0;i<150;i++){
        SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(s==INVALID_SOCKET){InterlockedIncrement(&failed);lasterr=WSAGetLastError();}else InterlockedIncrement(&ok);
        if(s!=INVALID_SOCKET&&connect(s,(struct sockaddr*)&d,sizeof(d))==0)send(s,"x",1,0);
        closesocket(s);
        SOCKET v=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(v==INVALID_SOCKET){InterlockedIncrement(&failed);lasterr=WSAGetLastError();}else InterlockedIncrement(&ok);
        sendto(v,"y",1,0,(struct sockaddr*)&u,sizeof(u));closesocket(v);
    }
    return 0;
}
int main(void){WSADATA w;int r=WSAStartup(MAKEWORD(2,2),&w);HANDLE h[4];
    for(int i=0;i<4;i++)h[i]=(HANDLE)_beginthreadex(0,0,worker,0,0,0);
    WaitForMultipleObjects(4,h,TRUE,INFINITE);printf("startup=%d ok=%ld failed=%ld err=%ld\n",r,ok,failed,lasterr);return 0;}
