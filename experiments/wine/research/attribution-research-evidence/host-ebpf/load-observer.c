#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct config {uint32_t server,pad;uint64_t current_address;};
struct record {uint32_t stage,actual_tgid,windows_pid,client_unix_pid,image_bytes,copy_bytes,stored_on_socket,port;uint16_t image[128];};
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    struct bpf_object *obj=bpf_object__open_file("observe.bpf.o",NULL);
    if(libbpf_get_error(obj) || bpf_object__load(obj)) return 3;
    struct config c={.server=strtoul(argv[1],NULL,10),.current_address=strtoull(argv[2],NULL,0)};
    uint32_t k=0;
    if(bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj,"config"),&k,&c,BPF_ANY))return 4;
    struct bpf_program *p;struct bpf_link *links[3];int n=0;
    bpf_object__for_each_program(p,obj) {
        links[n]=bpf_program__attach_lsm(p);
        if(libbpf_get_error(links[n]))return 5;
        n++;
    }
    FILE *ready=fopen("observer.ready","w");fputs("ready\n",ready);fclose(ready);
    for(int i=0;i<450 && access("observer.stop",F_OK);i++)usleep(100000);
    int fd=bpf_object__find_map_fd_by_name(obj,"observations");
    for(k=0;k<64;k++) {
        struct record r;
        if(bpf_map_lookup_elem(fd,&k,&r))continue;
        printf("event=%u stage=%u actual_tgid=%u winpid=%u client_unix_pid=%u storage=%u dport=%u image=",k,r.stage,r.actual_tgid,r.windows_pid,r.client_unix_pid,r.stored_on_socket,(r.port>>8)|((r.port&255)<<8));
        for(unsigned j=0;j<r.copy_bytes/2;j++)putchar(r.image[j]<128?r.image[j]:'?');
        putchar('\n');
    }
    for(int i=0;i<n;i++)bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
