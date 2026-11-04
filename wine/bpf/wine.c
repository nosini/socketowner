// SPDX-License-Identifier: GPL-2.0-only

// Optional Wine adapter. No native socketowner map is replaced.
//
// wineserver creates and connects Windows programs' sockets, so the kernel sees
// only wineserver. Which program asked is recoverable without reading Wine's
// private structures: every client thread has a request pipe, and the
// single-threaded server handles a request within the read which fetched it. A
// FIFO read by wineserver therefore names the client of the sockets which follow.
// Clients name themselves through public Windows layouts, so no build needs a
// profile. Creator records are immutable after socket_post_create returns: a
// failed connect or a different sender must not rewrite a socket's creator.
//
// A registered pasta carries a sandbox's traffic out through replacement
// sockets. Its connect joins each one to the inner flow which caused it. The
// inner packet is seen before it reaches pasta's TAP, so the record exists by
// then, and wine_flows is written before the host packet reaches mihomo.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define IMAGE_BYTES 1024
#define KNOWN 1
#define NO_CLIENT 2
#define NO_IMAGE 3
#define AMBIGUOUS_RELAY 6
#define NO_INNER_FLOW 7
#define NOT_WINE 8
#define S_IFMT 0170000
#define S_IFIFO 0010000
#define MAY_WRITE 2
#define MAY_READ 4
// pasta handles a SYN as soon as it reads the TAP; older records are leftovers.
#define RELAY_TTL_NS 2000000000ULL

struct inode { unsigned short i_mode; } __attribute__((preserve_access_index));
struct qstr { const unsigned char *name; unsigned int len; } __attribute__((preserve_access_index));
struct dentry { struct qstr d_name; } __attribute__((preserve_access_index));
struct path { struct dentry *dentry; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; struct path f_path; } __attribute__((preserve_access_index));
struct vm_area_struct { struct file *vm_file; } __attribute__((preserve_access_index));
struct net { __u64 net_cookie; } __attribute__((preserve_access_index));
struct nsproxy { struct net *net_ns; } __attribute__((preserve_access_index));
struct thread_struct { unsigned long gsbase; } __attribute__((preserve_access_index));
struct task_struct {
	struct task_struct *group_leader;
	struct nsproxy *nsproxy;
	struct thread_struct thread;
	__u64 start_boottime;
} __attribute__((preserve_access_index));
struct sock_common { unsigned short skc_num; } __attribute__((preserve_access_index));
struct sock { struct sock_common __sk_common; } __attribute__((preserve_access_index));
struct socket { short type; struct sock *sk; } __attribute__((preserve_access_index));
struct sockaddr { __u16 family, port; };
struct address {
	__u16 family;
	__be16 port;
	__u32 v4_or_flow;
	__u8 v6[16];
};
struct msghdr;
struct linux_binprm;
struct bpf_iter_task_vma { __u64 __opaque[1]; };
extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it, struct task_struct *task, __u64 addr) __ksym;
extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;

struct config {
	__u64 host_netns;
	__u32 sends, pad;
};
struct process_id {
	__u64 start_ns;
	__u32 tgid, pad;
};
struct server {
	__u64 start_ns;
};
// encoding 0 is a full UTF-16 Windows path, 1 a mapped file's basename in bytes.
struct client {
	__u64 start_ns, peb;
	__u32 status, image_bytes, encoding, windows_pid;
	__u16 image[IMAGE_BYTES / 2];
};
struct owner {
	__u64 socket_id, server_start_ns, client_start_ns, captured_boot_ns;
	__u32 server_tgid, uid, windows_pid, client_tgid;
	__u32 status, image_bytes, protocol, encoding;
	__u16 image[IMAGE_BYTES / 2];
};
struct storage {
	struct owner owner;
	__u32 ready, first_egress;
	__u32 sends, pad;
	// Used only in relay_flows, whose values are copies of this record.
	__u64 seen_ns;
	__u32 count, ambiguous;
};
struct pasta_target {
	__u64 netns;
	__u32 active, pad;
};
struct conn_key {
	__u64 netns;
	__u8 address[16];
	__u16 port;
	__u8 protocol, pad[5];
};
// TCP has no source port here: pasta's replacement socket does not know the
// inner one. Everything waiting for one destination shares a record, and
// mixed owners make it ambiguous rather than a guess by arrival order.
struct relay_key {
	__u64 netns;
	__u8 destination[16];
	__u16 destination_port, source_port;
	__u8 protocol, pad[3];
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
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} wine_config SEC(".maps");
// Keyed by the pipe's inode. A reused inode is safe: wineserver can't read a
// request before its client's write has replaced the entry.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct process_id);
} request_pipes SEC(".maps");
// The client each wineserver last read a request from.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct process_id);
} serving SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct server);
} servers SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct client);
} clients SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct client);
} blank_client SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct storage);
} wine_sockets SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct pasta_target);
} pasta_targets SEC(".maps");
// Public; see ../README.md. Written from the socket record itself, so the
// routing path does not depend on the diagnostic ring buffer.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct conn_key);
	__type(value, struct owner);
} wine_flows SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct relay_key);
	__type(value, struct storage);
} relay_flows SEC(".maps");
// An all-zero record: the update helper needs its value in map or stack memory,
// and this one is too large for the stack.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct storage);
} unlabelled SEC(".maps");
// Sandboxes with a wineserver. Cookies are never reused.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} relay_netns SEC(".maps");
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

// A name is no proof, but labels are cooperative anyway; see the README's limits.
static __always_inline int is_server(void)
{
	char c[16] = {};
	bpf_get_current_comm(c, sizeof(c));
	return c[0] == 'w' && c[1] == 'i' && c[2] == 'n' && c[3] == 'e' && c[4] == 's' &&
	       c[5] == 'e' && c[6] == 'r' && c[7] == 'v' && c[8] == 'e' && c[9] == 'r' && !c[10];
}

static __always_inline void lost_event(void)
{
	__u32 key = 1;
	__u64 *losses = bpf_map_lookup_elem(&counters, &key);
	if (losses)
		__sync_fetch_and_add(losses, 1);
}

static __always_inline void emit(struct storage *s, __u32 kind, struct flow *f)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_event();
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

// Tells userspace about a wineserver, and starts recording flows in its sandbox
// before any of its programs can have sent one.
static __always_inline void note_server(struct task_struct *task, __u32 tgid)
{
	struct task_struct *leader = task->group_leader;
	struct server *known = bpf_map_lookup_elem(&servers, &tgid);
	struct server record = { .start_ns = leader->start_boottime };
	struct nsproxy *ns = task->nsproxy;
	struct config *config;
	struct event *e;
	__u32 zero = 0, present = 1;
	__u64 netns;
	if ((known && known->start_ns == record.start_ns) || !ns)
		return;
	netns = ns->net_ns->net_cookie;
	config = bpf_map_lookup_elem(&wine_config, &zero);
	if (!config)
		return;
	bpf_map_update_elem(&servers, &tgid, &record, BPF_ANY);
	if (netns == config->host_netns)
		return;
	bpf_map_update_elem(&relay_netns, &netns, &present, BPF_ANY);
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		lost_event();
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->kind = 6;
	e->actor_tgid = tgid;
	e->flow.netns = netns;
	bpf_ringbuf_submit(e, 0);
}

// The first mapped file named *.exe, for 32-bit Linux clients, which have no
// 64-bit TEB: only the name is available this way.
static __always_inline int mapped_image(struct task_struct *task, struct client *c)
{
	struct bpf_iter_task_vma it;
	struct vm_area_struct *v;
	int found = 0;
	if (bpf_iter_task_vma_new(&it, task, 0)) {
		bpf_iter_task_vma_destroy(&it);
		return 0;
	}
	while ((v = bpf_iter_task_vma_next(&it))) {
		struct file *f = v->vm_file;
		const unsigned char *name;
		__u32 length, tail = 0;
		if (!f)
			continue;
		length = f->f_path.dentry->d_name.len;
		name = f->f_path.dentry->d_name.name;
		if (length < 5 || length > IMAGE_BYTES || bpf_probe_read_kernel(&tail, 4, name + length - 4) ||
		    (tail | 0x20202020) != 0x6578652e)
			continue;
		if (bpf_probe_read_kernel(c->image, length, name))
			continue;
		c->image_bytes = length;
		c->encoding = 1;
		found = 1;
		break;
	}
	bpf_iter_task_vma_destroy(&it);
	return found;
}

// These offsets are the Windows x86-64 TEB, PEB and process parameters: public
// layouts, not Wine's. TEB.Self confirms GS holds a TEB. A failure is retried on
// the client's next request, and leaves its sockets unknown until then.
static __always_inline void read_client(struct task_struct *task, struct client *c)
{
	__u64 teb = task->thread.gsbase, self = 0, peb = 0, parameters = 0, buffer = 0, id = 0;
	__u32 flags = 0;
	__u16 length = 0;
	if (!c->peb) {
		if (!teb || bpf_probe_read_user(&self, 8, (void *)(teb + 0x30)) || self != teb ||
		    bpf_probe_read_user(&peb, 8, (void *)(teb + 0x60)) || !peb) {
			if (mapped_image(task, c))
				c->status = KNOWN;
			return;
		}
		if (!bpf_probe_read_user(&id, 8, (void *)(teb + 0x40)) && id && id <= 0xffffffff)
			c->windows_pid = id;
		c->peb = peb;
	}
	peb = c->peb;
	if (bpf_probe_read_user(&parameters, 8, (void *)(peb + 0x20)) || !parameters ||
	    bpf_probe_read_user(&flags, 4, (void *)(parameters + 8)) || !(flags & 1) ||
	    bpf_probe_read_user(&length, 2, (void *)(parameters + 0x60)) ||
	    bpf_probe_read_user(&buffer, 8, (void *)(parameters + 0x68)) || !buffer)
		return;
	if (length < 2 || length > IMAGE_BYTES || (length & 1))
		return;
	if (bpf_probe_read_user(c->image, length, (void *)buffer))
		return;
	c->image_bytes = length;
	c->status = KNOWN;
}

SEC("lsm/file_permission")
int BPF_PROG(wine_file, struct file *file, int mask, int ret)
{
	struct task_struct *task;
	struct inode *inode;
	struct process_id *pipe, id = {};
	struct client *c;
	__u64 key;
	__u32 tgid, zero = 0;
	if (ret)
		return ret;
	inode = file->f_inode;
	if (!inode || (inode->i_mode & S_IFMT) != S_IFIFO || !(mask & (MAY_READ | MAY_WRITE)))
		return 0;
	key = (__u64)inode;
	task = bpf_get_current_task_btf();
	tgid = bpf_get_current_pid_tgid() >> 32;
	if (is_server()) {
		if (!(mask & MAY_READ))
			return 0;
		note_server(task, tgid);
		pipe = bpf_map_lookup_elem(&request_pipes, &key);
		if (pipe)
			bpf_map_update_elem(&serving, &tgid, pipe, BPF_ANY);
		else
			bpf_map_update_elem(&request_pipes, &key, &id, BPF_NOEXIST);
		return 0;
	}
	if (!(mask & MAY_WRITE) || !(pipe = bpf_map_lookup_elem(&request_pipes, &key)))
		return 0;
	id.tgid = tgid;
	id.start_ns = task->group_leader->start_boottime;
	bpf_map_update_elem(&request_pipes, &key, &id, BPF_EXIST);
	c = bpf_map_lookup_elem(&clients, &tgid);
	if (!c || c->start_ns != id.start_ns) {
		struct client *blank = bpf_map_lookup_elem(&blank_client, &zero);
		if (!blank)
			return 0;
		bpf_map_update_elem(&clients, &tgid, blank, BPF_ANY);
		c = bpf_map_lookup_elem(&clients, &tgid);
		if (!c)
			return 0;
		c->start_ns = id.start_ns;
	}
	if (c->status != KNOWN)
		read_client(task, c);
	return 0;
}

SEC("lsm/socket_post_create")
int BPF_PROG(wine_create, struct socket *socket, int family, int type, int protocol, int kern, int ret)
{
	struct task_struct *task;
	struct process_id *request;
	struct client *c = 0;
	struct storage *s;
	struct sock *sk;
	struct config *config;
	__u32 key = 0, tgid;
	__u64 *seq, id;
	if (ret)
		return ret;
	if (kern || (family != 2 && family != 10) || (type != 1 && type != 2))
		return 0;
	if (protocol && protocol != (type == 1 ? 6 : 17))
		return 0;
	sk = socket->sk;
	if (!sk || !is_server())
		return 0;
	task = bpf_get_current_task_btf();
	tgid = bpf_get_current_pid_tgid() >> 32;
	s = bpf_sk_storage_get(&wine_sockets, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!s || s->ready)
		return 0;
	seq = bpf_map_lookup_elem(&counters, &key);
	config = bpf_map_lookup_elem(&wine_config, &key);
	if (!seq || !config)
		return 0;
	id = __sync_fetch_and_add(seq, 1) + 1;
	s->owner.socket_id = id;
	s->owner.server_start_ns = task->group_leader->start_boottime;
	s->owner.captured_boot_ns = bpf_ktime_get_boot_ns();
	s->owner.server_tgid = tgid;
	s->owner.uid = bpf_get_current_uid_gid();
	s->owner.protocol = type == 1 ? 6 : 17;
	s->owner.status = NO_CLIENT;
	request = bpf_map_lookup_elem(&serving, &tgid);
	if (request && request->tgid) {
		s->owner.client_tgid = request->tgid;
		s->owner.client_start_ns = request->start_ns;
		s->owner.status = NO_IMAGE;
		c = bpf_map_lookup_elem(&clients, &request->tgid);
	}
	if (c && c->start_ns == request->start_ns && c->status == KNOWN &&
	    !bpf_probe_read_kernel(s->owner.image, IMAGE_BYTES, c->image)) {
		s->owner.windows_pid = c->windows_pid;
		s->owner.image_bytes = c->image_bytes;
		s->owner.encoding = c->encoding;
		s->owner.status = KNOWN;
	}
	s->sends = config->sends;
	// No other process can use this newly created socket before this hook
	// returns. All owner fields remain immutable from this point onward.
	__sync_lock_test_and_set(&s->ready, 1);
	emit(s, 3, 0);
	return 0;
}

static __always_inline __u64 next_socket_id(void)
{
	__u32 key = 0;
	__u64 *seq = bpf_map_lookup_elem(&counters, &key);
	return seq ? __sync_fetch_and_add(seq, 1) + 1 : 0;
}

// Each pasta socket joins at most one inner flow. Connect runs in pasta's only
// socket thread and precedes the first host packet.
static __always_inline void relay_connect(struct task_struct *task, struct pasta_target *t,
					  struct socket *socket, struct sock *sk, struct sockaddr *addr)
{
	struct relay_key k = {};
	struct address a = {};
	struct storage *s, *e;
	__u64 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 status = NO_INNER_FLOW, protocol;
	int fresh;
	if (socket->type != 1 && socket->type != 2)
		return;
	protocol = socket->type == 1 ? 6 : 17;
	if (bpf_probe_read_kernel(&a, sizeof(a), addr))
		return;
	if (a.family == 2) {
		k.destination[10] = k.destination[11] = 0xff;
		__builtin_memcpy(&k.destination[12], &a.v4_or_flow, 4);
	} else if (a.family == 10) {
		__builtin_memcpy(k.destination, a.v6, 16);
	} else {
		return;
	}
	s = bpf_sk_storage_get(&wine_sockets, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!s || s->ready)
		return;
	k.netns = t->netns;
	k.destination_port = bpf_ntohs(a.port);
	k.protocol = protocol;
	if (protocol == 17)
		k.source_port = sk->__sk_common.skc_num;
	e = bpf_map_lookup_elem(&relay_flows, &k);
	if (e) {
		fresh = protocol == 17 || bpf_ktime_get_boot_ns() - e->seen_ns <= RELAY_TTL_NS;
		if (!fresh)
			status = NO_INNER_FLOW;
		else if (e->ambiguous)
			status = AMBIGUOUS_RELAY;
		else if (!e->ready)
			status = NOT_WINE;
		else if (bpf_probe_read_kernel(&s->owner, sizeof(s->owner), &e->owner))
			status = NO_INNER_FLOW;
		else
			status = 0;
		if (protocol == 6 && (!fresh || __sync_fetch_and_add(&e->count, -1) <= 1))
			bpf_map_delete_elem(&relay_flows, &k);
	}
	if (status) {
		__builtin_memset(&s->owner, 0, sizeof(s->owner));
		s->owner.socket_id = next_socket_id();
		s->owner.server_start_ns = task->group_leader->start_boottime;
		s->owner.captured_boot_ns = bpf_ktime_get_boot_ns();
		s->owner.server_tgid = tgid;
		s->owner.uid = bpf_get_current_uid_gid();
		s->owner.protocol = protocol;
		s->owner.status = status;
	}
	if (!s->owner.socket_id)
		return;
	__sync_lock_test_and_set(&s->ready, 1);
	emit(s, 5, 0);
}

SEC("lsm/socket_connect")
int BPF_PROG(wine_connect, struct socket *socket, struct sockaddr *addr, int len, int ret)
{
	struct task_struct *task;
	struct pasta_target *t;
	struct storage *s;
	struct sock *sk;
	if (ret)
		return ret;
	sk = socket->sk;
	if (!sk)
		return 0;
	task = bpf_get_current_task_btf();
	t = bpf_task_storage_get(&pasta_targets, task->group_leader, 0, 0);
	if (t && t->active) {
		relay_connect(task, t, socket, sk, addr);
		return 0;
	}
	if (!(s = bpf_sk_storage_get(&wine_sockets, sk, 0, 0)) || !s->ready)
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

// exec replaces both the client's identity and a pasta's registration.
SEC("lsm/bprm_committed_creds")
int BPF_PROG(wine_exec, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct pasta_target *t = bpf_task_storage_get(&pasta_targets, task->group_leader, 0, 0);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (t)
		t->active = 0;
	bpf_map_delete_elem(&clients, &tgid);
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

static __always_inline int same_owner(struct storage *a, struct storage *b)
{
	if (!b)
		return !a->ready;
	return a->ready && a->owner.status == KNOWN && b->owner.status == KNOWN &&
	       a->owner.server_tgid == b->owner.server_tgid &&
	       a->owner.server_start_ns == b->owner.server_start_ns &&
	       a->owner.client_tgid == b->owner.client_tgid &&
	       a->owner.client_start_ns == b->owner.client_start_ns;
}

// Runs before the packet can reach pasta. Unlabelled flows are recorded too: a
// native program's SYN must not let pasta consume a Windows program's record.
static __always_inline void note_inner_flow(struct flow *f, struct storage *s)
{
	struct relay_key k = {};
	struct storage *p, *value;
	__u64 now = bpf_ktime_get_boot_ns();
	__u32 zero = 0;
	value = s ? s : bpf_map_lookup_elem(&unlabelled, &zero);
	if (!value)
		return;
	k.netns = f->netns;
	__builtin_memcpy(k.destination, f->destination, 16);
	k.destination_port = f->destination_port;
	k.protocol = f->protocol;
	if (f->protocol == 17) {
		// pasta keeps UDP source ports, which makes this key exact; a new
		// socket on the port replaces its predecessor's record.
		k.source_port = f->source_port;
		p = bpf_map_lookup_elem(&relay_flows, &k);
		if (p && (s ? p->owner.socket_id == s->owner.socket_id : !p->ready))
			return;
		bpf_map_update_elem(&relay_flows, &k, value, BPF_ANY);
		return;
	}
	if ((f->tcp_flags & 0x12) != 0x02)
		return;
	p = bpf_map_lookup_elem(&relay_flows, &k);
	if (p && now - p->seen_ns > RELAY_TTL_NS) {
		bpf_map_delete_elem(&relay_flows, &k);
		p = 0;
	}
	if (!p) {
		// NOEXIST keeps two CPUs from replacing each other's waiting record.
		int inserted = !bpf_map_update_elem(&relay_flows, &k, value, BPF_NOEXIST);
		p = bpf_map_lookup_elem(&relay_flows, &k);
		if (!p)
			return;
		if (inserted) {
			p->seen_ns = now;
			__sync_fetch_and_add(&p->count, 1);
			return;
		}
	}
	if (!same_owner(p, s))
		p->ambiguous = 1;
	p->seen_ns = now;
	__sync_fetch_and_add(&p->count, 1);
}

SEC("cgroup_skb/egress")
int wine_egress(struct __sk_buff *skb)
{
	struct storage *s;
	struct owner *published;
	struct conn_key key = {};
	struct flow f = {};
	struct bpf_sock *sk = skb->sk;
	if (!sk)
		return 1;
	s = bpf_sk_storage_get(&wine_sockets, sk, 0, 0);
	if (s && !s->ready)
		s = 0;
	if (!packet_flow(skb, &f))
		return 1;
	if (bpf_map_lookup_elem(&relay_netns, &f.netns))
		note_inner_flow(&f, s);
	key.netns = f.netns;
	__builtin_memcpy(key.address, f.source, 16);
	key.port = f.source_port;
	key.protocol = f.protocol;
	published = bpf_map_lookup_elem(&wine_flows, &key);
	if (!s) {
		// The port passed to a socket with no Windows identity.
		if (published)
			bpf_map_delete_elem(&wine_flows, &key);
		return 1;
	}
	// Active flows republish after LRU eviction, as conn_owners does.
	if (!published || published->socket_id != s->owner.socket_id)
		bpf_map_update_elem(&wine_flows, &key, &s->owner, BPF_ANY);
	if (!__sync_val_compare_and_swap(&s->first_egress, 0, 1))
		emit(s, 4, &f);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
