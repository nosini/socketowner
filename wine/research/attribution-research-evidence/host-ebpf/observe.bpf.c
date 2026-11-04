// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
struct sock {};
struct socket { struct sock *sk; } __attribute__((preserve_access_index));
struct sockaddr { unsigned short family, port; };
struct msghdr;
struct config { __u32 server, pad; __u64 current_address; };
struct record {
    __u32 stage, actual_tgid, windows_pid, client_unix_pid;
    __u32 image_bytes, copy_bytes, stored_on_socket, port;
    __u16 image[128];
};
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct config); } config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,__u32); } counter SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,64); __type(key,__u32); __type(value,struct record); } observations SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_SK_STORAGE); __uint(map_flags,BPF_F_NO_PREALLOC); __type(key,int); __type(value,struct record); } owners SEC(".maps");
static void publish(struct record *r) {
    __u32 zero=0,*n=bpf_map_lookup_elem(&counter,&zero);
    if(n) { __u32 k=__sync_fetch_and_add(n,1); bpf_map_update_elem(&observations,&k,r,BPF_ANY); }
}
static __always_inline int capture(struct socket *socket,__u32 port,__u32 stage) {
    __u32 zero=0,tgid=bpf_get_current_pid_tgid()>>32;
    struct config *cfg=bpf_map_lookup_elem(&config,&zero);
    if(!cfg || cfg->server!=tgid) return 0;
    __u64 thread=0,process=0,image=0;
    struct record r={.stage=stage,.actual_tgid=tgid,.port=port};
    if(bpf_probe_read_user(&thread,8,(void*)cfg->current_address) || !thread) return 0;
    if(bpf_probe_read_user(&process,8,(void*)(thread+136)) || !process) return 0;
    if(bpf_probe_read_user(&r.windows_pid,4,(void*)(process+152))) return 0;
    if(bpf_probe_read_user(&r.client_unix_pid,4,(void*)(process+188))) return 0;
    if(bpf_probe_read_user(&r.image_bytes,4,(void*)(process+252))) return 0;
    if(bpf_probe_read_user(&image,8,(void*)(process+256)) || !image) return 0;
    r.copy_bytes=r.image_bytes;
    if(r.copy_bytes>sizeof(r.image)) r.copy_bytes=sizeof(r.image);
    if(bpf_probe_read_user(r.image,r.copy_bytes,(void*)image)) return 0;
    struct sock *sk=socket->sk;
    if(!sk) return 0;
    struct record *saved=bpf_sk_storage_get(&owners,sk,0,BPF_SK_STORAGE_GET_F_CREATE);
    if(saved) { r.stored_on_socket=1; *saved=r; }
    publish(&r);
    return 0;
}
SEC("lsm/socket_post_create")
int BPF_PROG(on_create,struct socket *socket,int family,int type,int protocol,int kern,int ret) {
    if(ret) return ret;
    if((family!=2 && family!=10) || kern) return 0;
    return capture(socket,0,3);
}
SEC("lsm/socket_connect")
int BPF_PROG(on_connect,struct socket *socket,struct sockaddr *address,int addrlen,int ret) {
    if(ret) return ret;
    __u16 family=0,port=0;
    bpf_probe_read_kernel(&family,2,&address->family);
    if(family!=2 && family!=10) return 0;
    bpf_probe_read_kernel(&port,2,&address->port);
    return capture(socket,port,1);
}
SEC("lsm/socket_sendmsg")
int BPF_PROG(on_send,struct socket *socket,struct msghdr *msg,int size,int ret) {
    if(ret) return ret;
    struct sock *sk=socket->sk;
    if(!sk) return 0;
    struct record *saved=bpf_sk_storage_get(&owners,sk,0,0);
    if(!saved) return 0;
    saved->stage=2; saved->actual_tgid=bpf_get_current_pid_tgid()>>32;
    publish(saved);
    return 0;
}
char LICENSE[] SEC("license")="GPL";
