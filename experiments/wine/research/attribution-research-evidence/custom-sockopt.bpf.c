#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct {
    __uint(type,BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags,BPF_F_NO_PREALLOC);
    __type(key,int);
    __type(value,__u32);
} labels SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __uint(max_entries,1);
    __type(key,__u32);
    __type(value,__u32);
} observed SEC(".maps");
SEC("cgroup/setsockopt")
int annotate(struct bpf_sockopt *ctx) {
    if(ctx->level!=0x52534953 || ctx->optname!=1) return 1;
    __u32 *p=ctx->optval;
    if(ctx->optlen!=sizeof(*p) || (void*)(p+1)>ctx->optval_end) return 0;
    __u32 *v=bpf_sk_storage_get(&labels,ctx->sk,0,BPF_SK_STORAGE_GET_F_CREATE);
    if(!v) return 0;
    *v=*p;
    __u32 k=0;
    bpf_map_update_elem(&observed,&k,v,BPF_ANY);
    ctx->optlen=-1;
    return 1;
}
char LICENSE[] SEC("license")="GPL";
