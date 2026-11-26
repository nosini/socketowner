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
// A Windows program also opens sockets in its own Linux process: the resolver
// behind getaddrinfo, GStreamer, libldap. One lookup by TGID finds such a
// process in the clients map, and its sockets get the same identity, naming
// the wineserver that reads its requests rather than itself.
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
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define MAY_WRITE 2
#define MAY_READ 4
// Who created a socket, as the diagnostic events report it.
#define CREATED_SERVER 1
#define CREATED_CLIENT 2
// thread_info.status: a 32-bit syscall is active, so the task is compat.
#define TS_COMPAT 0x0002
// pasta handles a SYN as soon as it reads the TAP; older records are leftovers.
#define RELAY_TTL_NS 2000000000ULL
// A TCP relay record's count once it is retired: its last waiting flow was
// consumed, or it expired. Joining one fails, and only the CPU whose swap set
// it deletes the record.
#define RELAY_DEAD 0xffffffffU
// Swaps lost to other CPUs before a SYN or connect gives up on a record.
#define RELAY_TRIES 8
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

struct pipe_inode_info;
struct inode { unsigned short i_mode; unsigned long i_ino; struct pipe_inode_info *i_pipe; } __attribute__((preserve_access_index));
struct qstr { const unsigned char *name; unsigned int len; } __attribute__((preserve_access_index));
struct dentry { struct qstr d_name; } __attribute__((preserve_access_index));
struct path { struct dentry *dentry; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; struct path f_path; } __attribute__((preserve_access_index));
struct vm_area_struct { struct file *vm_file; } __attribute__((preserve_access_index));
struct net { __u64 net_cookie; } __attribute__((preserve_access_index));
struct nsproxy { struct net *net_ns; } __attribute__((preserve_access_index));
struct thread_struct { unsigned long gsbase; } __attribute__((preserve_access_index));
struct thread_info { __u32 status; } __attribute__((preserve_access_index));
struct task_struct {
	struct thread_info thread_info;
	struct task_struct *group_leader;
	struct nsproxy *nsproxy;
	struct thread_struct thread;
	__u64 start_boottime;
} __attribute__((preserve_access_index));
struct sock_common { unsigned short skc_num; } __attribute__((preserve_access_index));
struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
} __attribute__((preserve_access_index));
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
	// The client a request pipe names, and the wineserver that reads it:
	// a client's own sockets report that server, never their own TGID.
	__u64 start_ns, server_start_ns;
	__u32 tgid, server_tgid;
};
struct server {
	__u64 start_ns;
};
// encoding 0 is a full UTF-16 Windows path, 1 a mapped file's basename in bytes.
struct client {
	__u64 start_ns, peb;
	__u32 status, image_bytes, encoding, windows_pid;
	__u16 image[IMAGE_BYTES / 2];
	// The wineserver serving this client, recorded where the pipe pairing
	// names the client itself.
	__u64 server_start_ns;
	__u32 server_tgid, pad;
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
	// Creator of this socket: CREATED_SERVER or CREATED_CLIENT. A pasta
	// socket has none, so relay events leave the field empty.
	__u32 sends, creator;
	// Used only in relay_flows, whose values are copies of this record.
	// TCP and UDP records are stamped in their source before insertion, so
	// no copy is visible without them.
	__u64 seen_ns;
	__u32 count, ambiguous;
};
struct pasta_target {
	__u64 netns;
	__u32 active, pad;
};
// pasta's DNS forwarding sends queries to the host resolver instead of the
// address the client wrote to. Learned from pasta's command line when it is
// registered; see ../README.md.
struct forward_key {
	__u64 netns;
	__u8 address[16];
};
struct dns_forward {
	__u8 resolver[16];
};
struct conn_key {
	__u64 netns;
	__u8 address[16];
	__u16 port;
	__u8 protocol, pad[5];
};
// TCP has no source port here: pasta's replacement socket does not know the
// inner one. Everything waiting for one destination shares a record, and
// mixed owners make it ambiguous rather than a guess by arrival order. A TCP
// record also has a generation, which relay_heads names; UDP records and
// relay_heads keys have none.
struct relay_key {
	__u64 netns;
	__u8 destination[16];
	__u16 destination_port, source_port;
	__u8 protocol, pad[3];
	__u64 generation;
};
struct relay_head {
	__u64 generation;
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
	// 0, CREATED_SERVER or CREATED_CLIENT. The pad keeps the size at a
	// multiple of eight: the Go decoder counts no trailing padding.
	__u32 creator, pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} wine_config SEC(".maps");
// Keyed by the pipe's inode, by address and number. Entries outlive their
// pipes, and the kernel reuses a freed inode's memory for new pipes; the
// address alone made any process writing to such a pipe a client of a
// wineserver that once read the old one, so that all its sockets were
// labelled. pipefs numbers each new inode afresh, so the pair names one pipe.
// A pipe wineserver reads is still safe to reuse: it can't read a request
// before its client's write has replaced the entry.
struct pipe_key {
	__u64 inode, ino;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct pipe_key);
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
// Per-thread scratch for building a struct client before atomic publication
// into clients. Task-local storage (keyed by the running thread) is safe
// across preemption and sleepable bpf_copy_from_user.
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct client);
} client_scratch SEC(".maps");
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
// Public: wine_flows keyed by destination too, as socketowner's conn_flows,
// so that sockets sharing a source address and port keep their own records.
struct flow_key {
	__u64 netns;
	__u8 source[16], destination[16];
	__u16 source_port, destination_port;
	__u8 protocol, pad[3];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, struct owner);
} wine_peer_flows SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct relay_key);
	__type(value, struct storage);
} relay_flows SEC(".maps");
// The generation of each destination's current TCP record, which SYNs join and
// pasta's connects consume. A record is deleted only by the CPU that retired
// it, and its generation, from the socket ID sequence, is never used again, so
// no CPU can delete a record another is still updating or create one in its
// place: a SYN that can't join the current record publishes a new generation.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct relay_key);
	__type(value, struct relay_head);
} relay_heads SEC(".maps");
// DNS translations of registered pastas, keyed by the forward address as the
// sandbox sees it. Internal: the public Wine routing maps are unchanged.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 256);
	__type(key, struct forward_key);
	__type(value, struct dns_forward);
} dns_forwards SEC(".maps");
// A record with no owner: the update helper needs its value in map or stack
// memory, and this one is too large for the stack. Only the relay fields are
// ever written, each CPU writing the same count and a recent time.
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
	if (c[0] != 'w' || c[1] != 'i' || c[2] != 'n' || c[3] != 'e' || c[4] != 's' ||
	    c[5] != 'e' || c[6] != 'r' || c[7] != 'v' || c[8] != 'e' || c[9] != 'r')
		return 0;
	// Accept wineserver64, wineserver32, and distribution binaries such as
	// wineserver-development, whose task comm is truncated at 15 bytes.
	return !c[10] || (c[10] == '6' && c[11] == '4' && !c[12]) ||
	       (c[10] == '3' && c[11] == '2' && !c[12]) || c[10] == '-';
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
	e->creator = s->creator;
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
	if (netns == config->host_netns) {
		bpf_map_update_elem(&servers, &tgid, &record, BPF_ANY);
		return;
	}
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
	// Mark the server known only once its event is queued, so a lost event
	// is retried on the server's next request.
	bpf_map_update_elem(&servers, &tgid, &record, BPF_ANY);
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
		    (tail | 0x20202000) != 0x6578652e)
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

static __always_inline long read_user_mem(void *dst, __u32 size, const void *src, int sleepable)
{
	if (sleepable)
		return bpf_copy_from_user(dst, size, src);
	return bpf_probe_read_user(dst, size, src);
}

// These offsets are the Windows x86-64 TEB, PEB and process parameters: public
// layouts, not Wine's. TEB.Self confirms GS holds a TEB. A 64-bit client can
// fail that check before its GS is set, so such a failure is retried on its
// next request, and leaves its sockets unknown until then. Only compat (32-bit)
// tasks use the mapped-image fallback, which can name but not path them.
// Callers build into private scratch storage so a failed read never corrupts a
// published record. When sleepable is non-zero, bpf_copy_from_user faults in
// swapped-out user pages.
static __always_inline void read_client(struct task_struct *task, struct client *c, int sleepable)
{
	__u64 teb = task->thread.gsbase, self = 0, peb = 0, parameters = 0, buffer = 0, id = 0;
	__u32 flags = 0;
	__u16 length = 0;
	if (!c->peb) {
		if (task->thread_info.status & TS_COMPAT) {
			if (mapped_image(task, c))
				c->status = KNOWN;
			return;
		}
		if (!teb || read_user_mem(&self, 8, (void *)(teb + 0x30), sleepable) || self != teb ||
		    read_user_mem(&peb, 8, (void *)(teb + 0x60), sleepable) || !peb)
			return;
		c->peb = peb;
	}
	// The Windows PID is retried independently of the PEB, in case its read
	// faulted or returned zero before ProcessParameters was ready.
	if (!c->windows_pid && teb) {
		if (self != teb)
			read_user_mem(&self, 8, (void *)(teb + 0x30), sleepable);
		if (self == teb && !read_user_mem(&id, 8, (void *)(teb + 0x40), sleepable) &&
		    id && id <= 0xffffffff)
			c->windows_pid = id;
	}
	peb = c->peb;
	if (read_user_mem(&parameters, 8, (void *)(peb + 0x20), sleepable) || !parameters ||
	    read_user_mem(&flags, 4, (void *)(parameters + 8), sleepable) || !(flags & 1) ||
	    read_user_mem(&length, 2, (void *)(parameters + 0x60), sleepable) ||
	    read_user_mem(&buffer, 8, (void *)(parameters + 0x68), sleepable) || !buffer)
		return;
	if (length < 2 || length > IMAGE_BYTES || (length & 1))
		return;
	if (read_user_mem(c->image, length, (void *)buffer, sleepable))
		return;
	c->image_bytes = length;
	c->status = KNOWN;
}

// Updates clients[tgid] atomically from thread-local scratch so readers never
// observe a half-initialized record (such as server_tgid without
// server_start_ns) or a failed read zeroing a published KNOWN image.
static __always_inline void update_client(struct task_struct *task, __u32 tgid, __u64 start_ns,
					  __u32 server_tgid, __u64 server_start_ns, int sleepable)
{
	struct client *c = bpf_map_lookup_elem(&clients, &tgid);
	struct client *scratch;
	int same_proc = c && c->start_ns == start_ns;
	int have_server = server_tgid && server_start_ns;
	int need_server = have_server &&
			  (!same_proc || c->server_tgid != server_tgid || c->server_start_ns != server_start_ns);
	if (same_proc && c->status == KNOWN && !need_server)
		return;
	scratch = bpf_task_storage_get(&client_scratch, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!scratch)
		return;
	if (same_proc) {
		if (bpf_probe_read_kernel(scratch, sizeof(*scratch), c) || scratch->start_ns != start_ns) {
			__builtin_memset(scratch, 0, sizeof(*scratch));
			scratch->start_ns = start_ns;
			same_proc = 0;
		}
	} else {
		__builtin_memset(scratch, 0, sizeof(*scratch));
		scratch->start_ns = start_ns;
	}
	if (have_server) {
		scratch->server_tgid = server_tgid;
		scratch->server_start_ns = server_start_ns;
	}
	if (scratch->status != KNOWN)
		read_client(task, scratch, sleepable);
	if (!same_proc) {
		if (!c) {
			if (bpf_map_update_elem(&clients, &tgid, scratch, BPF_NOEXIST) == 0)
				goto done;
		} else {
			bpf_map_update_elem(&clients, &tgid, scratch, BPF_ANY);
			goto done;
		}
	}
	// Re-check the published entry so a concurrent thread's progress
	// (such as resolving KNOWN or recording a wineserver) is never lost.
	c = bpf_map_lookup_elem(&clients, &tgid);
	if (!c || c->start_ns != start_ns) {
		bpf_map_update_elem(&clients, &tgid, scratch, BPF_ANY);
		goto done;
	}
	if (c->status == KNOWN) {
		if (scratch->status != KNOWN) {
			if (!have_server ||
			    (c->server_tgid == server_tgid && c->server_start_ns == server_start_ns))
				goto done;
			if (bpf_probe_read_kernel(scratch, sizeof(*scratch), c) || scratch->start_ns != start_ns)
				goto done;
			scratch->server_tgid = server_tgid;
			scratch->server_start_ns = server_start_ns;
		}
		bpf_map_update_elem(&clients, &tgid, scratch, BPF_ANY);
		goto done;
	}
	if (!scratch->server_tgid && c->server_tgid && c->server_start_ns) {
		scratch->server_tgid = c->server_tgid;
		scratch->server_start_ns = c->server_start_ns;
	}
	if (scratch->status == KNOWN ||
	    scratch->server_tgid != c->server_tgid ||
	    scratch->server_start_ns != c->server_start_ns ||
	    scratch->peb != c->peb ||
	    scratch->windows_pid != c->windows_pid)
		bpf_map_update_elem(&clients, &tgid, scratch, BPF_ANY);
done:
	bpf_task_storage_delete(&client_scratch, task);
}

SEC("lsm/file_permission")
int BPF_PROG(wine_file, struct file *file, int mask, int ret)
{
	struct task_struct *task;
	struct inode *inode;
	struct process_id *pipe, id = {};
	struct pipe_key key = {};
	__u32 tgid;
	if (ret)
		return ret;
	inode = file->f_inode;
	if (!inode || (inode->i_mode & S_IFMT) != S_IFIFO || !(mask & (MAY_READ | MAY_WRITE)))
		return 0;
	key.inode = (__u64)inode;
	key.ino = inode->i_ino;
	task = bpf_get_current_task_btf();
	tgid = bpf_get_current_pid_tgid() >> 32;
	if (is_server()) {
		if (!(mask & MAY_READ))
			return 0;
		note_server(task, tgid);
		pipe = bpf_map_lookup_elem(&request_pipes, &key);
		if (pipe) {
			bpf_map_update_elem(&serving, &tgid, pipe, BPF_ANY);
			// One wineserver reads a given pipe, but a takeover or a
			// reused TGID must not leave a predecessor naming a
			// client's sockets. The client identity keeps waiting for
			// its next write, as before.
			if (pipe->server_tgid != tgid ||
			    pipe->server_start_ns != task->group_leader->start_boottime) {
				struct process_id record = *pipe;
				record.server_tgid = tgid;
				record.server_start_ns = task->group_leader->start_boottime;
				bpf_map_update_elem(&request_pipes, &key, &record, BPF_EXIST);
			}
			return 0;
		}
		// This pipe's client hasn't written since the observer started,
		// or its request_pipes entry was evicted. Don't attribute a
		// socket in this request to the previous client: blank serving
		// means no client. The entry does name its wineserver.
		id.server_tgid = tgid;
		id.server_start_ns = task->group_leader->start_boottime;
		bpf_map_update_elem(&request_pipes, &key, &id, BPF_NOEXIST);
		bpf_map_update_elem(&serving, &tgid, &id, BPF_ANY);
		return 0;
	}
	if (!(mask & MAY_WRITE) || !(pipe = bpf_map_lookup_elem(&request_pipes, &key)))
		return 0;
	id.tgid = tgid;
	id.start_ns = task->group_leader->start_boottime;
	id.server_tgid = pipe->server_tgid;
	id.server_start_ns = pipe->server_start_ns;
	bpf_map_update_elem(&request_pipes, &key, &id, BPF_EXIST);
	// The wineserver which reads this pipe serves this client, so the
	// client's own sockets can name it. A write with no server named leaves
	// server fields unset: wine_create refuses to label without a server
	// rather than put the client's own TGID in the server fields.
	update_client(task, tgid, id.start_ns, id.server_tgid, id.server_start_ns, 0);
	return 0;
}

// Prunes closed pipes from request_pipes once all ends have closed, so exited
// Wine threads do not accumulate and evict live idle request pipes.
// pipe_release clears inode->i_pipe before security_file_free runs when the
// last reader and writer close; while either end stays open, i_pipe remains
// non-NULL so buffered requests can still be attributed.
SEC("lsm/file_free_security")
int BPF_PROG(wine_file_free, struct file *file)
{
	struct inode *inode = file->f_inode;
	struct pipe_key key = {};
	if (!inode || (inode->i_mode & S_IFMT) != S_IFIFO)
		return 0;
	if (inode->i_pipe)
		return 0;
	key.inode = (__u64)inode;
	key.ino = inode->i_ino;
	if (bpf_map_lookup_elem(&request_pipes, &key))
		bpf_map_delete_elem(&request_pipes, &key);
	return 0;
}

// Fills a fresh owner with a client's identity: the client's TGID and start
// time, and its image once read. A client whose image could not be read keeps
// no-image, exactly as a wineserver-created socket for it would.
static __always_inline void label_from_client(struct owner *o, struct client *c, __u32 tgid)
{
	o->client_tgid = tgid;
	o->client_start_ns = c->start_ns;
	o->status = NO_IMAGE;
	if (c->status != KNOWN)
		return;
	if (bpf_probe_read_kernel(o->image, IMAGE_BYTES, c->image))
		return;
	o->windows_pid = c->windows_pid;
	o->image_bytes = c->image_bytes;
	o->encoding = c->encoding;
	o->status = KNOWN;
}

SEC("lsm.s/socket_post_create")
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
	int server;
	if (ret)
		return ret;
	if (kern || (family != 2 && family != 10) || (type != 1 && type != 2))
		return 0;
	if (protocol && protocol != (type == 1 ? 6 : 17))
		return 0;
	sk = socket->sk;
	if (!sk)
		return 0;
	server = is_server();
	task = bpf_get_current_task_btf();
	tgid = bpf_get_current_pid_tgid() >> 32;
	if (!server) {
		__u64 start_ns = task->group_leader->start_boottime;
		// A Windows program also opens sockets in its own Linux process:
		// the resolver behind getaddrinfo, GStreamer, libldap. Reading the
		// current task and one lookup by TGID are all this path costs
		// every other process; the start time rules out a reused PID, and
		// a forked child, which has its own TGID and never wrote a
		// request, stays unlabelled.
		c = bpf_map_lookup_elem(&clients, &tgid);
		if (!c || c->start_ns != start_ns)
			return 0;
		// Only a client whose wineserver is known is labelled: always
		// the one reading its pipe. The client's own TGID never names a
		// server.
		if (!c->server_tgid || !c->server_start_ns)
			return 0;
		// Retry reading the client's PEB/ImagePathName in this sleepable
		// hook so swapped-out pages are faulted in with bpf_copy_from_user.
		if (c->status != KNOWN) {
			update_client(task, tgid, start_ns, c->server_tgid, c->server_start_ns, 1);
			c = bpf_map_lookup_elem(&clients, &tgid);
			if (!c || c->start_ns != start_ns || !c->server_tgid || !c->server_start_ns)
				return 0;
		}
	}
	s = bpf_sk_storage_get(&wine_sockets, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (!s || s->ready)
		return 0;
	seq = bpf_map_lookup_elem(&counters, &key);
	config = bpf_map_lookup_elem(&wine_config, &key);
	if (!seq || !config)
		return 0;
	id = __sync_fetch_and_add(seq, 1) + 1;
	s->owner.socket_id = id;
	s->owner.captured_boot_ns = bpf_ktime_get_boot_ns();
	s->owner.uid = bpf_get_current_uid_gid();
	s->owner.protocol = type == 1 ? 6 : 17;
	if (server) {
		s->owner.server_start_ns = task->group_leader->start_boottime;
		s->owner.server_tgid = tgid;
		s->owner.status = NO_CLIENT;
		request = bpf_map_lookup_elem(&serving, &tgid);
		if (request && request->tgid) {
			s->owner.client_tgid = request->tgid;
			s->owner.client_start_ns = request->start_ns;
			s->owner.status = NO_IMAGE;
			c = bpf_map_lookup_elem(&clients, &request->tgid);
			if (c && c->start_ns == request->start_ns)
				label_from_client(&s->owner, c, request->tgid);
		}
		s->creator = CREATED_SERVER;
	} else {
		// The same identity a wineserver-created socket for this client
		// gets, with the client's wineserver in the server fields.
		s->owner.server_tgid = c->server_tgid;
		s->owner.server_start_ns = c->server_start_ns;
		label_from_client(&s->owner, c, tgid);
		s->creator = CREATED_CLIENT;
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

// A record stamped after now was read is fresh, not expired by the difference
// wrapping around.
static __always_inline int relay_expired(__u64 now, __u64 seen)
{
	return now > seen && now - seen > RELAY_TTL_NS;
}

// Retires a TCP record seen with count c. It fails if the count changed, as a
// joining SYN changes it after refreshing the time. k names the record.
static __always_inline int relay_retire(struct relay_key *k, struct storage *p, __u32 c)
{
	if (__sync_val_compare_and_swap(&p->count, c, RELAY_DEAD) != c)
		return 0;
	bpf_map_delete_elem(&relay_flows, k);
	return 1;
}

// The identity a record gives pasta's socket, copied into s, or why it gives
// none.
static __always_inline __u32 relay_status(struct storage *e, struct storage *s)
{
	if (e->ambiguous)
		return AMBIGUOUS_RELAY;
	if (!e->ready)
		return NOT_WINE;
	if (bpf_probe_read_kernel(&s->owner, sizeof(s->owner), &e->owner))
		return NO_INNER_FLOW;
	return 0;
}

// Consumes one waiting flow of the current TCP record for k, whose generation
// is set here, and returns its status. The connect serves a flow whose SYN was
// recorded in full before it reached pasta, so a SYN still being recorded can
// only add an ambiguity this flow does not need.
static __always_inline __u32 relay_consume(struct relay_key *k, struct storage *s)
{
	struct relay_head *head = bpf_map_lookup_elem(&relay_heads, k);
	struct storage *e;
	__u32 status, c;
	int i;
	if (!head)
		return NO_INNER_FLOW;
	k->generation = READ_ONCE(head->generation);
	if (!k->generation)
		return NO_INNER_FLOW;
	e = bpf_map_lookup_elem(&relay_flows, k);
	if (!e)
		return NO_INNER_FLOW;
	for (i = 0; i < RELAY_TRIES; i++) {
		c = READ_ONCE(e->count);
		if (c == RELAY_DEAD || !c)
			return NO_INNER_FLOW;
		if (relay_expired(bpf_ktime_get_boot_ns(), READ_ONCE(e->seen_ns))) {
			if (relay_retire(k, e, c))
				return NO_INNER_FLOW;
			continue;
		}
		status = relay_status(e, s);
		if (__sync_val_compare_and_swap(&e->count, c, c == 1 ? RELAY_DEAD : c - 1) == c) {
			if (c == 1)
				bpf_map_delete_elem(&relay_flows, k);
			return status;
		}
	}
	return NO_INNER_FLOW;
}

// Each pasta socket joins at most one inner flow. Connect runs in pasta's only
// socket thread and precedes the first host packet.
static __always_inline void relay_connect(struct task_struct *task, struct pasta_target *t,
					  struct socket *socket, struct sock *sk, struct sockaddr *addr,
					  int len)
{
	struct relay_key k = {};
	struct address a = {};
	struct storage *s, *e;
	__u64 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 status = NO_INNER_FLOW, protocol;
	if (socket->type == SOCK_STREAM) {
		if (sk->sk_protocol && sk->sk_protocol != 6)
			return;
		protocol = 6;
	} else if (socket->type == SOCK_DGRAM) {
		if (sk->sk_protocol && sk->sk_protocol != 17)
			return;
		protocol = 17;
	} else {
		return;
	}
	if (len < 16)
		return;
	if (bpf_probe_read_kernel(&a.family, sizeof(a.family), &addr->family))
		return;
	if (a.family == 2) {
		if (bpf_probe_read_kernel(&a, 8, addr))
			return;
		k.destination[10] = k.destination[11] = 0xff;
		__builtin_memcpy(&k.destination[12], &a.v4_or_flow, 4);
	} else if (a.family == 10) {
		if (len < 24 || bpf_probe_read_kernel(&a, sizeof(a), addr))
			return;
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
	if (protocol == 17) {
		k.source_port = sk->__sk_common.skc_num;
		e = bpf_map_lookup_elem(&relay_flows, &k);
		if (e) {
			if (!relay_expired(bpf_ktime_get_boot_ns(), READ_ONCE(e->seen_ns)))
				status = relay_status(e, s);
			bpf_map_delete_elem(&relay_flows, &k);
		}
	} else {
		status = relay_consume(&k, s);
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
		relay_connect(task, t, socket, sk, addr, len);
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

// Joins a SYN to a TCP record. The time is refreshed before the count, so a
// CPU that read the record as expired fails to retire it once this SYN is
// counted. Returns 1 when joined, 0 when the record is retired and a new one
// is needed, and -1 when another CPU changed it first.
static __always_inline int relay_join(struct relay_key *k, struct storage *p, struct storage *s, __u64 now)
{
	__u32 c = READ_ONCE(p->count);
	if (c == RELAY_DEAD || !c)
		return 0;
	if (relay_expired(now, READ_ONCE(p->seen_ns)))
		return relay_retire(k, p, c) ? 0 : -1;
	p->seen_ns = now;
	if (__sync_val_compare_and_swap(&p->count, c, c + 1) != c)
		return -1;
	// Counted before marked: a connect in between serves another flow,
	// recorded in full, which this SYN's owner does not concern.
	if (!same_owner(p, s))
		p->ambiguous = 1;
	return 1;
}

// Runs before the packet can reach pasta. Unlabelled flows are recorded too: a
// native program's SYN must not let pasta consume a Windows program's record.
static __always_inline void note_inner_flow(struct flow *f, struct storage *s)
{
	struct relay_key k = {};
	struct relay_head *head, none = {};
	struct storage *p, *value;
	__u64 now = bpf_ktime_get_boot_ns(), generation;
	__u32 zero = 0;
	int i, joined;
	value = s ? s : bpf_map_lookup_elem(&unlabelled, &zero);
	if (!value)
		return;
	k.netns = f->netns;
	__builtin_memcpy(k.destination, f->destination, 16);
	// pasta's DNS forwarding sends a query to the host resolver instead of
	// the address the client wrote to, and it keeps the source port, so the
	// record keeps an exact key by using the destination pasta connects to.
	// Port 53 only: a flow pasta does not map must keep its own destination,
	// and pasta versions disagree about 853.
	if (f->destination_port == 53) {
		struct forward_key fk = {};
		struct dns_forward *forward;
		fk.netns = f->netns;
		__builtin_memcpy(fk.address, f->destination, 16);
		forward = bpf_map_lookup_elem(&dns_forwards, &fk);
		if (forward)
			__builtin_memcpy(k.destination, forward->resolver, 16);
	}
	k.destination_port = f->destination_port;
	k.protocol = f->protocol;
	if (f->protocol == 17) {
		// pasta keeps UDP source ports, which makes this key exact; a new
		// socket on the port replaces its predecessor's record.
		k.source_port = f->source_port;
		p = bpf_map_lookup_elem(&relay_flows, &k);
		if (p && (s ? p->owner.socket_id == s->owner.socket_id : !p->ready)) {
			p->seen_ns = now;
			return;
		}
		value->seen_ns = now;
		value->count = 1;
		value->ambiguous = 0;
		bpf_map_update_elem(&relay_flows, &k, value, BPF_ANY);
		return;
	}
	if ((f->tcp_flags & 0x12) != 0x02)
		return;
	head = bpf_map_lookup_elem(&relay_heads, &k);
	if (!head) {
		bpf_map_update_elem(&relay_heads, &k, &none, BPF_NOEXIST);
		head = bpf_map_lookup_elem(&relay_heads, &k);
		if (!head)
			return;
	}
	// A new record is published with its time and count already set, so no
	// CPU ever sees it expired or without this SYN. The fields are the
	// source's own, not its owner's, and any concurrent writer stores the
	// same count and a recent time.
	value->seen_ns = now;
	value->count = 1;
	value->ambiguous = 0;
	for (i = 0; i < RELAY_TRIES; i++) {
		generation = READ_ONCE(head->generation);
		k.generation = generation;
		p = generation ? bpf_map_lookup_elem(&relay_flows, &k) : 0;
		if (p) {
			joined = relay_join(&k, p, s, now);
			if (joined > 0)
				return;
			if (joined < 0)
				continue;
		}
		// No live record: publish a new generation. Its key is unique, so
		// the insert creates it, and only the CPU whose swap names it in
		// the head has its SYN recorded there; the others remove theirs,
		// which no CPU could find, and join the winner's.
		k.generation = next_socket_id();
		if (!k.generation || bpf_map_update_elem(&relay_flows, &k, value, BPF_NOEXIST))
			break;
		if (__sync_val_compare_and_swap(&head->generation, generation, k.generation) == generation)
			return;
		bpf_map_delete_elem(&relay_flows, &k);
	}
	// This SYN is unrecorded, and its connect would consume another flow's
	// record: make the current one ambiguous, so that it names neither.
	k.generation = READ_ONCE(head->generation);
	p = k.generation ? bpf_map_lookup_elem(&relay_flows, &k) : 0;
	if (p)
		p->ambiguous = 1;
}

SEC("cgroup_skb/egress")
int wine_egress(struct __sk_buff *skb)
{
	struct storage *s;
	struct owner *published, *peer_published;
	struct conn_key key = {};
	struct flow_key peer = {};
	struct flow f = {};
	struct bpf_sock *sk = skb->sk;
	if (!sk)
		return 1;
	// Kernel-generated RST/ACK replies leave from a per-CPU SOCK_RAW TCP
	// control socket. It has no user owner or Wine identity, so ignore it
	// rather than removing the record of the flow it answers for.
	sk = bpf_sk_fullsock(sk);
	if (!sk || (sk->type != SOCK_STREAM && sk->type != SOCK_DGRAM))
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
	peer.netns = f.netns;
	__builtin_memcpy(peer.source, f.source, 16);
	__builtin_memcpy(peer.destination, f.destination, 16);
	peer.source_port = f.source_port;
	peer.destination_port = f.destination_port;
	peer.protocol = f.protocol;
	published = bpf_map_lookup_elem(&wine_flows, &key);
	peer_published = bpf_map_lookup_elem(&wine_peer_flows, &peer);
	if (!s) {
		// The port, or this flow, passed to a socket with no Windows
		// identity.
		if (published)
			bpf_map_delete_elem(&wine_flows, &key);
		if (peer_published)
			bpf_map_delete_elem(&wine_peer_flows, &peer);
		return 1;
	}
	// Active flows republish after LRU eviction, as conn_owners does.
	if (!published || published->socket_id != s->owner.socket_id)
		bpf_map_update_elem(&wine_flows, &key, &s->owner, BPF_ANY);
	if (!peer_published || peer_published->socket_id != s->owner.socket_id)
		bpf_map_update_elem(&wine_peer_flows, &peer, &s->owner, BPF_ANY);
	if (!__sync_val_compare_and_swap(&s->first_egress, 0, 1))
		emit(s, 4, &f);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
