// Optional diagnostic Wine adapter. No native socketowner map is replaced.
// Only a pidfd-registered task with a matching executable may supply metadata.
// Creator records are immutable after socket_post_create returns: a failed
// connect or a different sender must not rewrite a socket's creator.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define IMAGE_BYTES 1024
#define KNOWN 1
#define READ_FAILED 2
#define INVALID_IMAGE 3
#define CHANGED_REQUEST 4
#define INVALID_PROCESS 5

struct inode { unsigned long i_ino; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; } __attribute__((preserve_access_index));
struct mm_struct { struct file *exe_file; } __attribute__((preserve_access_index));
struct task_struct {
	struct task_struct *group_leader;
	struct mm_struct *mm;
	__u64 start_boottime;
} __attribute__((preserve_access_index));
struct sock {};
struct socket { struct sock *sk; } __attribute__((preserve_access_index));
struct sockaddr { __u16 family, port; };
struct msghdr;
struct linux_binprm;
struct bpf_iter_meta;
struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

struct target_config {
	__u64 current_address, exe_inode, kernel_exe;
	__u32 thread_process, process_id, process_unix_pid;
	__u32 process_start, process_img_len, process_image, active, sends;
};
struct owner {
	__u64 socket_id, server_start_ns, windows_start_time, captured_boot_ns;
	__u32 server_tgid, uid, windows_pid, client_unix_pid;
	__u32 status, image_bytes, protocol, pad;
	__u16 image[IMAGE_BYTES / 2];
};
struct storage {
	struct owner owner;
	__u32 ready, first_egress;
	__u32 sends, pad;
};
struct flow {
	__u64 netns;
	__u8 source[16], destination[16];
	__u16 source_port, destination_port;
	__u8 family, protocol, valid, tcp_flags;
};
struct event {
	__u32 kind, actor_tgid;
	struct flow flow;
	struct owner owner;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct target_config);
} wine_targets SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct storage);
} wine_sockets SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");
// Sequence numbers are private to this observer lifetime, not Linux cookies.
// Slot 1 counts event-buffer losses; this is diagnostics, never routing authority.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline struct target_config *target(struct task_struct *task)
{
	struct target_config *c;
	struct file *exe;
	struct mm_struct *mm = task->mm;
	__u64 pid = bpf_get_current_pid_tgid();
	if ((__u32)pid != pid >> 32 || !mm)
		return 0;
	c = bpf_task_storage_get(&wine_targets, task->group_leader, 0, 0);
	if (!c || !c->active || !c->kernel_exe)
		return 0;
	exe = mm->exe_file;
	if (!exe || (__u64)exe != c->kernel_exe)
		return 0;
	return c;
}

// Bind to the kernel-held executable file, not a userspace dev_t encoding.
// Filesystems may report per-subvolume st_dev values. The selected task's
// mm holds this file reference until exec, whose LSM hook revokes registration.
SEC("iter/task")
int wine_seed(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct target_config *c;
	struct mm_struct *mm;
	struct file *exe;
	struct inode *inode;
	if (!task || task->group_leader != task || !(mm = task->mm))
		return 0;
	c = bpf_task_storage_get(&wine_targets, task, 0, 0);
	if (!c || !c->active || c->kernel_exe)
		return 0;
	exe = mm->exe_file;
	if (!exe || !(inode = exe->f_inode) || inode->i_ino != c->exe_inode) {
		c->active = 0;
		return 0;
	}
	c->kernel_exe = (__u64)exe;
	return 0;
}

static __always_inline void emit(struct storage *s, __u32 kind, struct flow *f)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 key = 1;
		__u64 *losses = bpf_map_lookup_elem(&counters, &key);
		if (losses)
			__sync_fetch_and_add(losses, 1);
		return;
	}
	e->kind = kind;
	e->actor_tgid = bpf_get_current_pid_tgid() >> 32;
	if (f)
		e->flow = *f;
	else
		__builtin_memset(&e->flow, 0, sizeof(e->flow));
	e->owner = s->owner;
	bpf_ringbuf_submit(e, 0);
}

// A read failure produces an unknown record for this new socket. Nothing falls
// back to a previous socket's cached name, a short path, or the last request.
static __always_inline __u32 read_creator(struct target_config *c, struct owner *o)
{
	__u64 thread = 0, process = 0, image = 0, again = 0;
	__u32 length = 0, id = 0;
	__u64 start = 0;
	if (bpf_probe_read_user(&thread, 8, (void *)c->current_address) || !thread ||
	    bpf_probe_read_user(&process, 8, (void *)(thread + c->thread_process)) || !process)
		return READ_FAILED;
	if (bpf_probe_read_user(&o->windows_pid, 4, (void *)(process + c->process_id)) ||
	    bpf_probe_read_user(&o->client_unix_pid, 4, (void *)(process + c->process_unix_pid)) ||
	    bpf_probe_read_user(&o->windows_start_time, 8, (void *)(process + c->process_start)) ||
	    bpf_probe_read_user(&length, 4, (void *)(process + c->process_img_len)) ||
	    bpf_probe_read_user(&image, 8, (void *)(process + c->process_image)))
		return READ_FAILED;
	if (!o->windows_pid || !o->client_unix_pid || o->client_unix_pid > 0x7fffffff || !o->windows_start_time)
		return INVALID_PROCESS;
	if (!image || length < 2 || length > IMAGE_BYTES || (length & 1))
		return INVALID_IMAGE;
	if (bpf_probe_read_user(o->image, length, (void *)image))
		return READ_FAILED;
	if (bpf_probe_read_user(&again, 8, (void *)c->current_address) || again != thread ||
	    bpf_probe_read_user(&again, 8, (void *)(thread + c->thread_process)) || again != process ||
	    bpf_probe_read_user(&again, 8, (void *)(process + c->process_image)) || again != image ||
	    bpf_probe_read_user(&id, 4, (void *)(process + c->process_id)) || id != o->windows_pid ||
	    bpf_probe_read_user(&start, 8, (void *)(process + c->process_start)) || start != o->windows_start_time ||
	    bpf_probe_read_user(&id, 4, (void *)(process + c->process_img_len)) || id != length)
		return CHANGED_REQUEST;
	o->image_bytes = length;
	return KNOWN;
}

SEC("lsm/socket_post_create")
int BPF_PROG(wine_create, struct socket *socket, int family, int type, int protocol, int kern, int ret)
{
	struct task_struct *task;
	struct target_config *c;
	struct storage *s;
	struct sock *sk;
	__u32 key = 0;
	__u64 *seq, id;
	if (ret)
		return ret;
	if (kern || (family != 2 && family != 10) || (type != 1 && type != 2))
		return 0;
	if (protocol && protocol != (type == 1 ? 6 : 17))
		return 0;
	sk = socket->sk;
	if (!sk)
		return 0;
	task = bpf_get_current_task_btf();
	if (!(c = target(task)))
		return 0;
	s = bpf_sk_storage_get(&wine_sockets, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!s || s->ready)
		return 0;
	seq = bpf_map_lookup_elem(&counters, &key);
	if (!seq)
		return 0;
	id = __sync_fetch_and_add(seq, 1) + 1;
	if (!id) {
		c->active = 0;
		return 0;
	}
	s->owner.socket_id = id;
	s->owner.server_start_ns = task->group_leader->start_boottime;
	s->owner.captured_boot_ns = bpf_ktime_get_boot_ns();
	s->owner.server_tgid = bpf_get_current_pid_tgid() >> 32;
	s->owner.uid = bpf_get_current_uid_gid();
	s->owner.protocol = type == 1 ? 6 : 17;
	s->owner.status = read_creator(c, &s->owner);
	s->sends = c->sends;
	// No other process can use this newly created socket before this hook
	// returns. All owner fields remain immutable from this point onward.
	__sync_lock_test_and_set(&s->ready, 1);
	emit(s, 3, 0);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(wine_connect, struct socket *socket, struct sockaddr *addr, int len, int ret)
{
	struct storage *s;
	struct sock *sk;
	if (ret)
		return ret;
	sk = socket->sk;
	if (!sk || !(s = bpf_sk_storage_get(&wine_sockets, sk, 0, 0)) || !s->ready)
		return 0;
	// Report the operation, not a successful connection. In particular,
	// EISCONN from another holder must not reassign the creator identity.
	emit(s, 1, 0);
	return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(wine_send, struct socket *socket, struct msghdr *msg, int size, int ret)
{
	struct storage *s;
	struct sock *sk;
	if (ret)
		return ret;
	sk = socket->sk;
	if (!sk || !(s = bpf_sk_storage_get(&wine_sockets, sk, 0, 0)) || !s->ready || !s->sends)
		return 0;
	emit(s, 2, 0);
	return 0;
}

SEC("lsm/bprm_committed_creds")
int BPF_PROG(wine_exec, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct target_config *c = bpf_task_storage_get(&wine_targets, task->group_leader, 0, 0);
	if (c)
		c->active = 0;
	return 0;
}

static __always_inline int packet_flow(struct __sk_buff *skb, struct flow *f)
{
	__u8 first, proto;
	__u16 frag;
	__u32 off;
	if (bpf_skb_load_bytes(skb, 0, &first, 1))
		return 0;
	if ((first >> 4) == 4) {
		off = (first & 15) * 4;
		if (off < 20 || bpf_skb_load_bytes(skb, 9, &proto, 1) ||
		    bpf_skb_load_bytes(skb, 6, &frag, 2) || (bpf_ntohs(frag) & 0x1fff))
			return 0;
		f->family = 4;
		f->source[10] = f->source[11] = 0xff;
		f->destination[10] = f->destination[11] = 0xff;
		if (bpf_skb_load_bytes(skb, 12, &f->source[12], 4) ||
		    bpf_skb_load_bytes(skb, 16, &f->destination[12], 4))
			return 0;
	} else if ((first >> 4) == 6) {
		f->family = 6;
		off = 40;
		if (bpf_skb_load_bytes(skb, 6, &proto, 1) ||
		    bpf_skb_load_bytes(skb, 8, f->source, 16) ||
		    bpf_skb_load_bytes(skb, 24, f->destination, 16))
			return 0;
		for (int i = 0; i < 8; i++) {
			__u8 h[2];
			if (proto == 6 || proto == 17)
				break;
			if (bpf_skb_load_bytes(skb, off, h, 2))
				return 0;
			if (proto == 44) {
				if (bpf_skb_load_bytes(skb, off + 2, &frag, 2) || (bpf_ntohs(frag) & 0xfff8))
					return 0;
				off += 8;
			} else if (proto == 0 || proto == 43 || proto == 60) {
				off += (h[1] + 1) * 8;
			} else if (proto == 51) {
				off += (h[1] + 2) * 4;
			} else {
				return 0;
			}
			proto = h[0];
		}
	} else {
		return 0;
	}
	if ((proto != 6 && proto != 17) || bpf_skb_load_bytes(skb, off, &f->source_port, 2) ||
	    bpf_skb_load_bytes(skb, off + 2, &f->destination_port, 2))
		return 0;
	if (proto == 6 && bpf_skb_load_bytes(skb, off + 13, &f->tcp_flags, 1))
		return 0;
	f->source_port = bpf_ntohs(f->source_port);
	f->destination_port = bpf_ntohs(f->destination_port);
	f->protocol = proto;
	f->netns = bpf_get_netns_cookie(skb);
	f->valid = 1;
	return 1;
}

SEC("cgroup_skb/egress")
int wine_egress(struct __sk_buff *skb)
{
	struct storage *s;
	struct flow f = {};
	struct bpf_sock *sk = skb->sk;
	if (!sk || !(s = bpf_sk_storage_get(&wine_sockets, sk, 0, 0)) || !s->ready)
		return 1;
	if (!packet_flow(skb, &f) || __sync_val_compare_and_swap(&s->first_egress, 0, 1))
		return 1;
	emit(s, 4, &f);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
