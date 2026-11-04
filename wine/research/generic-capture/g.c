// SPDX-License-Identifier: GPL-2.0-only

// Prototype: attribute wineserver's sockets through the request pipe, and name
// the client from its PEB. No Wine-internal layout is read.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define IMG 1024
#define S_IFMT 0170000
#define S_IFIFO 0010000
struct inode { unsigned short i_mode; } __attribute__((preserve_access_index));
struct qstr { const unsigned char *name; unsigned int len; } __attribute__((preserve_access_index));
struct dentry { struct qstr d_name; } __attribute__((preserve_access_index));
struct path { struct dentry *dentry; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; struct path f_path; } __attribute__((preserve_access_index));
struct vm_area_struct { struct file *vm_file; } __attribute__((preserve_access_index));
struct bpf_iter_task_vma { __u64 __opaque[1]; };
extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it, struct task_struct *task, __u64 addr) __ksym;
extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;
struct thread_struct { unsigned long gsbase; } __attribute__((preserve_access_index));
struct task_struct { struct thread_struct thread; } __attribute__((preserve_access_index));
struct sock {};
struct socket { struct sock *sk; } __attribute__((preserve_access_index));
struct msghdr;
struct image { __u32 status, bytes; __u64 peb; __u32 pad0, pad; __u16 path[IMG / 2]; };
struct label { __u32 client, seq; };
struct ev { __u32 kind, server, client, status, bytes, a; __u16 path[IMG / 2]; };
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, __u64); __type(value, __u32); } pipes SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 1024); __type(key, __u32); __type(value, __u32); } serving SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, struct image); } images SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct image); } blank SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_SK_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, int); __type(value, struct label); } labels SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 24); } events SEC(".maps");
// 0 created 1 no-client 2 no-image 3 send-ok 4 send-MISMATCH 5 ring-loss
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 7); __type(key, __u32); __type(value, __u64); } counts SEC(".maps");
static __always_inline void count(__u32 k) { __u64 *c = bpf_map_lookup_elem(&counts, &k); if (c) __sync_fetch_and_add(c, 1); }
static __always_inline int is_server(void)
{
	char c[16] = {};
	bpf_get_current_comm(c, sizeof(c));
	return c[0]=='w'&&c[1]=='i'&&c[2]=='n'&&c[3]=='e'&&c[4]=='s'&&c[5]=='e'&&c[6]=='r'&&c[7]=='v'&&c[8]=='e'&&c[9]=='r'&&!c[10];
}
// The first mapped file named *.exe, for clients with no reachable 64-bit TEB.
static __always_inline int mapped_image(struct task_struct *t, struct image *m)
{
	struct bpf_iter_task_vma it;
	struct vm_area_struct *v;
	int found = 0;
	if (bpf_iter_task_vma_new(&it, t, 0)) {
		bpf_iter_task_vma_destroy(&it);
		return 0;
	}
	while ((v = bpf_iter_task_vma_next(&it))) {
		struct file *f = v->vm_file;
		const unsigned char *name;
		__u32 len, tail = 0;
		if (!f)
			continue;
		len = f->f_path.dentry->d_name.len;
		name = f->f_path.dentry->d_name.name;
		if (len < 5 || len > IMG || bpf_probe_read_kernel(&tail, 4, name + len - 4) ||
		    (tail | 0x20202020) != 0x6578652e)
			continue;
		if (bpf_probe_read_kernel(m->path, len, name))
			continue;
		m->bytes = len;
		found = 1;
		break;
	}
	bpf_iter_task_vma_destroy(&it);
	return found;
}
static __always_inline void read_image(struct image *m)
{
	struct task_struct *t = bpf_get_current_task_btf();
	__u64 teb = t->thread.gsbase, self = 0, peb = 0, params = 0, buffer = 0;
	__u32 flags = 0;
	__u16 length = 0;
	// GS is only trustworthy before a WOW64 thread first runs 32-bit code, which
	// the first requests precede. One process has one PEB, so keep what they found.
	if (!m->peb) {
		if (!teb || bpf_probe_read_user(&self, 8, (void *)(teb + 0x30)) || self != teb ||
		    bpf_probe_read_user(&peb, 8, (void *)(teb + 0x60)) || !peb) {
			m->status = mapped_image(t, m) ? 6 : 2;
			return;
		}
		m->peb = peb;
	}
	peb = m->peb;
	if (bpf_probe_read_user(&params, 8, (void *)(peb + 0x20)) || !params ||
	    bpf_probe_read_user(&flags, 4, (void *)(params + 8)) || !(flags & 1) ||
	    bpf_probe_read_user(&length, 2, (void *)(params + 0x60)) ||
	    bpf_probe_read_user(&buffer, 8, (void *)(params + 0x68)) || !buffer) { m->status = 3; return; }
	if (length < 2 || length > IMG || (length & 1)) { m->status = 4; return; }
	if (bpf_probe_read_user(m->path, length & (IMG - 1) ? length : IMG, (void *)buffer)) { m->status = 5; return; }
	m->bytes = length;
	m->status = 1;
}
SEC("lsm/file_permission")
int BPF_PROG(perm, struct file *file, int mask, int ret)
{
	struct inode *inode;
	__u64 key;
	__u32 tgid, zero = 0, *p;
	if (ret)
		return ret;
	inode = file->f_inode;
	if (!inode || (inode->i_mode & S_IFMT) != S_IFIFO || !(mask & 6))
		return 0;
	key = (__u64)inode;
	tgid = bpf_get_current_pid_tgid() >> 32;
	if (is_server()) {
		if (!(mask & 4))
			return 0;
		p = bpf_map_lookup_elem(&pipes, &key);
		if (!p) {
			bpf_map_update_elem(&pipes, &key, &zero, BPF_NOEXIST);
			return 0;
		}
		bpf_map_update_elem(&serving, &tgid, p, BPF_ANY);
		return 0;
	}
	if (!(mask & 2) || !(p = bpf_map_lookup_elem(&pipes, &key)))
		return 0;
	*p = tgid;
	struct image *m = bpf_map_lookup_elem(&images, &tgid);
	if (!m) {
		struct image *b = bpf_map_lookup_elem(&blank, &zero);
		if (!b)
			return 0;
		bpf_map_update_elem(&images, &tgid, b, BPF_NOEXIST);
		m = bpf_map_lookup_elem(&images, &tgid);
		if (!m)
			return 0;
	}
	if (m->status != 1 && m->status != 6)
		read_image(m);
	return 0;
}
SEC("lsm/socket_post_create")
int BPF_PROG(create, struct socket *socket, int family, int type, int protocol, int kern, int ret)
{
	__u32 server, *client;
	struct image *m;
	struct label *l;
	struct ev *e;
	struct sock *sk;
	if (ret || kern || (family != 2 && family != 10) || (type != 1 && type != 2))
		return ret;
	count(6);
	if (!is_server()) {
		return 0;
	}
	if (!(sk = socket->sk))
		return 0;
	server = bpf_get_current_pid_tgid() >> 32;
	count(0);
	client = bpf_map_lookup_elem(&serving, &server);
	if (!client || !*client) {
		count(1);
		return 0;
	}
	l = bpf_sk_storage_get(&labels, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (l)
		l->client = *client;
	m = bpf_map_lookup_elem(&images, client);
	if (!m || (m->status != 1 && m->status != 6))
		count(2);
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count(5);
		return 0;
	}
	e->kind = 1; e->server = server; e->client = *client; e->a = type;
	e->status = m ? m->status : 0;
	e->bytes = 0;
	if (m && (m->status == 1 || m->status == 6)) {
		e->bytes = m->bytes;
		bpf_probe_read_kernel(e->path, IMG, m->path);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}
SEC("lsm/socket_sendmsg")
int BPF_PROG(sendmsg, struct socket *socket, struct msghdr *msg, int size, int ret)
{
	struct label *l;
	struct sock *sk = socket->sk;
	__u32 tgid;
	if (ret || !sk || !(l = bpf_sk_storage_get(&labels, sk, 0, 0)) || is_server())
		return ret;
	tgid = bpf_get_current_pid_tgid() >> 32;
	count(tgid == l->client ? 3 : 4);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
