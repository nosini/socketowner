// Controlled request objects, not Wine. Used to test profile admission and
// failure/lifetime cases independently of a real Wine build's startup services.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <uchar.h>
#include <errno.h>

struct process {
	uint64_t padding;
	uint32_t id;
	int unix_pid;
	uint64_t start_time;
	uint32_t imagelen;
	uint32_t reserved;
	char16_t *image;
};
struct thread { uint64_t padding; struct process *process; };
struct thread *current;
static char16_t alpha[] = u"\\??\\C:\\fixtures\\alpha.exe";
static char16_t beta[] = u"\\??\\C:\\fixtures\\beta.exe";
static char16_t invalid[] = { 'C', ':', '\\', 0xd800, '.', 'e', 'x', 'e' };

static int connect_tcp(int family, int port) {
	int fd = socket(family, SOCK_STREAM, 0), r;
	if (fd < 0) return -1;
	if (family == AF_INET) {
		struct sockaddr_in a = { .sin_family=AF_INET, .sin_port=htons(port), .sin_addr.s_addr=htonl(INADDR_LOOPBACK) };
		r = connect(fd, (struct sockaddr *)&a, sizeof(a));
	} else {
		struct sockaddr_in6 a = { .sin6_family=AF_INET6, .sin6_port=htons(port), .sin6_addr=IN6ADDR_LOOPBACK_INIT };
		r = connect(fd, (struct sockaddr *)&a, sizeof(a));
	}
	if (r) { close(fd); return -1; }
	return fd;
}
static int datagram(int family, int port) {
	int fd=socket(family, SOCK_DGRAM, 0);
	if(fd<0) return -1;
	if(family==AF_INET) {
		struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
		if(sendto(fd,"udp",3,0,(struct sockaddr*)&a,sizeof(a))!=3) { close(fd);return -1; }
	} else {
		struct sockaddr_in6 a={.sin6_family=AF_INET6,.sin6_port=htons(port),.sin6_addr=IN6ADDR_LOOPBACK_INIT};
		if(sendto(fd,"udp",3,0,(struct sockaddr*)&a,sizeof(a))!=3) { close(fd);return -1; }
	}
	close(fd);return 0;
}
int main(int argc,char **argv) {
	if(argc!=5)return 2;
	setbuf(stdout,NULL);
	struct process p={.id=101,.unix_pid=getpid(),.start_time=11111111,.imagelen=sizeof(alpha)-2,.image=alpha};
	struct thread t={.process=&p}; current=&t;
	int tcp=-1,c;
	printf("ready pid=%d\n",getpid());
	while((c=getchar())!=EOF) {
		if(c=='\n')continue;
		int ok=1;
		switch(c) {
		case '4': if(tcp>=0)close(tcp);tcp=connect_tcp(AF_INET,atoi(argv[1]));ok=tcp>=0;break;
		case '6': if(tcp>=0)close(tcp);tcp=connect_tcp(AF_INET6,atoi(argv[3]));ok=tcp>=0;break;
		case 'd': ok=!datagram(AF_INET,atoi(argv[2]));break;
		case 'e': ok=!datagram(AF_INET6,atoi(argv[4]));break;
		case 's': ok=tcp>=0 && send(tcp,"tcp",3,0)==3;break;
		case 'c': {
			struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(atoi(argv[1])),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
			ok=tcp>=0 && connect(tcp,(struct sockaddr*)&a,sizeof(a))<0 && errno==EISCONN;break;
		}
		case 'f': {
			pid_t child=fork();
			if(!child) _exit(tcp>=0 && send(tcp,"child",5,0)==5?0:1);
			int status=0;ok=child>0 && waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status);break;
		}
		case 'g': {
			pid_t child=fork();
			if(!child) { int fd=connect_tcp(AF_INET,atoi(argv[1]));if(fd<0)_exit(1);close(fd);_exit(0); }
			int status=0;ok=child>0 && waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status);break;
		}
		case 'b': p.id=202;p.start_time=22222222;p.image=beta;p.imagelen=sizeof(beta)-2;break;
		case 'u': p.image=invalid;p.imagelen=sizeof(invalid);break;
		case 'l': p.imagelen=4096;break;
		case 'n': current=NULL;break;
		case 'r': current=&t;p.id=101;p.start_time=11111111;p.image=alpha;p.imagelen=sizeof(alpha)-2;break;
		case 'x': execl("/bin/sleep","sleep","3",NULL);return 3;
		case 'q': if(tcp>=0)close(tcp);return 0;
		default: return 4;
		}
		printf("done %c %d\n",c,ok);
		if(!ok)return 5;
	}
	if(tcp>=0)close(tcp);
	return 0;
}
