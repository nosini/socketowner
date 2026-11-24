// SPDX-License-Identifier: GPL-2.0-only

// Records the executable of every process, so that mihomo can name the owner
// of a connection (see sockowner.c) without reading other processes' /proc
// entries.
//
// Each process carries its record in exec_tasks, task-local storage of its
// thread group leader, which userspace looks up with a pidfd. An LSM hook sets
// it when the process executes a program, and a new process starts with a
// copy of its parent's. The record goes away with the process, so the map
// can't fill up or keep stale entries. When a process is freed, its record is
// copied to exec_recent, keyed by process ID, which keeps the most recent
// processes so connections of short-lived ones can still be named; exec also
// writes there, so it holds new programs before their process is freed.
//
// A process that has been reaped can't be looked up by pidfd any more, but
// its record only reaches exec_recent once the task is freed, which can be
// much later. So when a process first sends on or connects a socket, its
// record is saved in exec_recent too, and the owner of a connection can still
// be named right after it exits. These hooks also record the process that
// sends on a connected socket as its owner, which the cgroup hooks in
// sockowner.c don't see.
//
// Every record carries the process's start time. A record only belongs to a
// connection's owner if the process started before the owner was recorded and,
// once it has exited, exited after that. This rules out process IDs that were
// reused in between.
//
// Only LSM hooks record, because the kernel skips tracing programs (tp_btf,
// fentry, kprobes) on a CPU where the same program was preempted, and a
// missed fork would leave a process without a record. LSM programs are never
// skipped.
//
// seed_tasks is an iterator the loader runs once after attaching, to add the
// processes that were already running.
//
// The socket hooks also save the path of the socket user's cgroup v2 in
// cgroup_paths, keyed by cgroup ID, the first time they see that cgroup on a
// socket, so that mihomo can name the cgroup sockowner.c publishes for a
// connection without reading cgroupfs. IDs aren't reused, so an entry stays
// right after the cgroup is removed.
//
// Unlike sockowner.c, these programs read kernel structures (relocated with
// BTF) and call bpf_d_path, so loading them needs CAP_PERFMON in addition to
// CAP_BPF, and the kernel needs CONFIG_BPF_LSM with "bpf" among its active
// LSMs.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "sockowner.h"

#define CLONE_THREAD 0x00010000

// Long enough for nearly every executable; paths that don't fit are recorded
// with len set to -ENAMETOOLONG.
#define EXEC_PATH_SIZE 1024

// Kernel structures, reduced to the fields used here. The loader relocates
// field offsets against the running kernel's BTF.
struct path {
	void *mnt;
	void *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

struct mm_struct {
	struct file *exe_file;
} __attribute__((preserve_access_index));

struct vm_area_struct {
	struct mm_struct *vm_mm;
} __attribute__((preserve_access_index));

// Before Linux 6.15 the parent pointer was called parent.
struct kernfs_node {
	struct kernfs_node *__parent;
	const char *name;
	__u64 id;
} __attribute__((preserve_access_index));

struct kernfs_node___old {
	struct kernfs_node *parent;
} __attribute__((preserve_access_index));

struct cgroup {
	struct kernfs_node *kn;
} __attribute__((preserve_access_index));

struct css_set {
	struct cgroup *dfl_cgrp;
} __attribute__((preserve_access_index));

struct task_struct {
	int pid;
	int tgid;
	__u64 start_boottime;
	struct task_struct *group_leader;
	struct css_set *cgroups;
} __attribute__((preserve_access_index));

// Iterating a task's VMAs holds a reference to its mm, which also keeps the
// mm's exe_file alive while bpf_d_path reads it.
struct bpf_iter_task_vma { __u64 __opaque[1]; };
extern int bpf_iter_task_vma_new(struct bpf_iter_task_vma *it,
				 struct task_struct *task, __u64 addr) __ksym;
extern struct vm_area_struct *bpf_iter_task_vma_next(struct bpf_iter_task_vma *it) __ksym;
extern void bpf_iter_task_vma_destroy(struct bpf_iter_task_vma *it) __ksym;

struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
} __attribute__((preserve_access_index));

struct socket {
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr;
struct sockaddr;

struct bpf_iter_meta;

struct bpf_iter__task {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

struct exec_path {
	__u64 start_ns; // CLOCK_BOOTTIME when the process started
	__u64 exit_ns;  // CLOCK_BOOTTIME when it was freed, or 0
	__s32 len;      // bytes in path including the NUL, or a negative errno
	__u32 pad;
	char path[EXEC_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct exec_path);
} exec_tasks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 2048);
	__type(key, __u32);
	__type(value, struct exec_path);
} exec_recent SEC(".maps");

// Paths of cgroups relative to the cgroup v2 root, such as
// /user.slice/user-1000.slice/session-2.scope, or / for the root itself.
#define CGROUP_PATH_SIZE 1024
// Components further from the root than this are not followed; such a path is
// recorded with len set to -ENAMETOOLONG, as is one longer than the buffer.
#define CGROUP_DEPTH_MAX 32
// kernfs names are at most NAME_MAX bytes.
#define CGROUP_NAME_SIZE 256
#define ENAMETOOLONG 36

struct cgroup_path {
	__s32 len; // bytes in path including the NUL, or a negative errno
	__u32 pad;
	char path[CGROUP_PATH_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct cgroup_path);
} cgroup_paths SEC(".maps");

// A cgroup_path with room for one more name past its end, so a name can be
// copied before its length is known, and the cgroups on the way to the root.
struct cgroup_scratch {
	struct cgroup_path p;
	char overflow[CGROUP_NAME_SIZE];
	__u64 chain[CGROUP_DEPTH_MAX];
};

// The socket hooks can be preempted by another task running the same hook on
// the same CPU, so they build in storage of the current task.
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgroup_scratch);
} cgroup_scratch SEC(".maps");

// Space to build a record in, as it's too large for the stack. The exec hook
// can sleep and be preempted, so it uses storage of the executing task rather
// than a per-CPU buffer.
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct exec_path);
} exec_scratch SEC(".maps");

// The same for the iterator, of which only one runs at a time.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_path);
} seed_scratch SEC(".maps");

// The update helper copies a whole record, so this also tells whether the
// storage now holds what the caller wrote or something another program wrote.
static __always_inline int same_record(const struct exec_path *a,
				       const struct exec_path *b)
{
	const __u8 *pa = (const __u8 *)a, *pb = (const __u8 *)b;

	for (int i = 0; i < sizeof(*a); i++)
		if (pa[i] != pb[i])
			return 0;
	return 1;
}

// Fills in the path of a task's current executable. The VMA iterator pins the
// task's mm for as long as the iterator lives, so its exe_file can't be freed
// by a concurrent exit or exec while bpf_d_path reads it. The caller sets
// start_ns. A task without an mm (kernel thread or exited) has no record.
static __always_inline int record_exe_path(struct task_struct *task,
					   struct exec_path *e)
{
	struct bpf_iter_task_vma it;
	struct vm_area_struct *v;
	struct mm_struct *mm;
	struct file *exe;
	int found = 0;

	if (bpf_iter_task_vma_new(&it, task, 0)) {
		bpf_iter_task_vma_destroy(&it);
		return 0;
	}
	v = bpf_iter_task_vma_next(&it);
	if (v && (mm = v->vm_mm) && (exe = mm->exe_file)) {
		e->exit_ns = 0;
		e->len = bpf_d_path(&exe->f_path, e->path, sizeof(e->path));
		found = 1;
	}
	bpf_iter_task_vma_destroy(&it);
	return found;
}

// Called once a new program has replaced the process image; bprm->file is the
// program that runs, which for a script is its interpreter, as in
// /proc/<pid>/exe. A thread that executes has become the thread group leader
// by now and taken over the process's ID and start time.
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(record_exec, struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u32 tgid = task->tgid;
	struct exec_path *e, *stored;

	e = bpf_task_storage_get(&exec_scratch, task, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!e)
		return 0;
	e->start_ns = task->start_boottime;
	e->exit_ns = 0;
	e->len = bpf_d_path(&bprm->file->f_path, e->path, sizeof(e->path));
	bpf_map_update_elem(&exec_recent, &tgid, e, BPF_ANY);
	// Storage is only initialised when it's created, so replace it rather
	// than writing into it, which a reader could see half done. Until the
	// new record is in place, readers find it in exec_recent.
	bpf_task_storage_delete(&exec_tasks, task);
	// The seeding iterator can create the storage between the delete and
	// the create, using an exe_file it read before the exec. Its record
	// would then survive because create doesn't replace an existing one.
	// Detect that and replace it once more.
	stored = bpf_task_storage_get(&exec_tasks, task, e,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!stored || !same_record(stored, e)) {
		bpf_task_storage_delete(&exec_tasks, task);
		bpf_task_storage_get(&exec_tasks, task, e,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	}
	bpf_task_storage_delete(&exec_scratch, task);
	return 0;
}

// Called for every new task before it gets its ID. The hook decides whether
// the fork may go ahead: ret is the verdict of the BPF LSM programs that ran
// before this one, which must stand, and this one never denies.
SEC("lsm/task_alloc")
int BPF_PROG(record_fork, struct task_struct *task, unsigned long clone_flags,
	     int ret)
{
	struct task_struct *parent = bpf_get_current_task_btf()->group_leader;
	struct exec_path *e;

	if (ret)
		return ret;
	if (clone_flags & CLONE_THREAD)
		return 0;
	e = bpf_task_storage_get(&exec_tasks, parent, 0, 0);
	if (e) {
		e = bpf_task_storage_get(&exec_tasks, task, e,
					 BPF_LOCAL_STORAGE_GET_F_CREATE);
		// The task's own start time isn't set yet. Nothing can look
		// the record up before the task has an ID.
		if (e)
			e->start_ns = bpf_ktime_get_boot_ns();
		return 0;
	}
	// The parent hasn't been seeded yet. Build the child's record from the
	// parent's executable so a child the iterator has already passed still
	// gets one, and its descendants inherit it.
	e = bpf_task_storage_get(&exec_scratch, task, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!e)
		return 0;
	if (record_exe_path(parent, e)) {
		e->start_ns = bpf_ktime_get_boot_ns();
		bpf_task_storage_get(&exec_tasks, task, e,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	}
	bpf_task_storage_delete(&exec_scratch, task);
	return 0;
}

// Called when the last reference to a task goes, after it has been reaped.
// After a thread executed, the old leader is freed as an ordinary thread, so
// only tasks that still lead their group count.
SEC("lsm/task_free")
int BPF_PROG(record_free, struct task_struct *task)
{
	__u32 tgid = task->tgid;
	struct exec_path *e;

	if (task->group_leader != task || !tgid)
		return 0;
	e = bpf_task_storage_get(&exec_tasks, task, 0, 0);
	if (!e || bpf_map_update_elem(&exec_recent, &tgid, e, BPF_ANY))
		return 0;
	e = bpf_map_lookup_elem(&exec_recent, &tgid);
	if (e)
		e->exit_ns = bpf_ktime_get_boot_ns();
	return 0;
}

static __always_inline struct kernfs_node *kn_parent(struct kernfs_node *kn)
{
	if (bpf_core_field_exists(kn->__parent))
		return BPF_CORE_READ(kn, __parent);
	return BPF_CORE_READ((struct kernfs_node___old *)kn, parent);
}

// Saves the path of the current task's cgroup v2 in cgroup_paths unless it's
// there, and returns its ID, or 0 if it couldn't be read. Names are read from
// the leaf up and then written from the root down.
static __always_inline __u64 save_cgroup_path(struct task_struct *task)
{
	struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn);
	struct cgroup_scratch *s;
	__u64 id;
	__u32 off = 0;
	int depth = 0;

	if (!kn)
		return 0;
	id = BPF_CORE_READ(kn, id);
	if (!id || bpf_map_lookup_elem(&cgroup_paths, &id))
		return id;
	s = bpf_task_storage_get(&cgroup_scratch, task, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		return 0;
	s->p.len = 0;
	s->p.pad = 0;
	for (int i = 0; i <= CGROUP_DEPTH_MAX; i++) {
		struct kernfs_node *parent = kn_parent(kn);

		if (!parent) // kn is the root, whose name isn't part of a path
			break;
		if (depth == CGROUP_DEPTH_MAX) {
			s->p.len = -ENAMETOOLONG;
			break;
		}
		s->chain[depth & (CGROUP_DEPTH_MAX - 1)] = (__u64)kn;
		depth++;
		kn = parent;
	}
	if (!s->p.len && !depth) {
		s->p.path[0] = '/';
		s->p.path[1] = 0;
		s->p.len = 2;
	}
	for (int i = CGROUP_DEPTH_MAX - 1; i >= 0 && !s->p.len; i--) {
		const char *name;
		long n;

		if (i >= depth)
			continue;
		if (off >= CGROUP_PATH_SIZE) {
			s->p.len = -ENAMETOOLONG;
			break;
		}
		kn = (struct kernfs_node *)s->chain[i & (CGROUP_DEPTH_MAX - 1)];
		name = BPF_CORE_READ(kn, name);
		s->p.path[off] = '/';
		off++;
		if (off >= CGROUP_PATH_SIZE) {
			s->p.len = -ENAMETOOLONG;
			break;
		}
		// Room for CGROUP_NAME_SIZE bytes is left past off.
		n = bpf_probe_read_kernel_str(&s->p.path[off], CGROUP_NAME_SIZE, name);
		if (n <= 0) {
			s->p.len = n ? n : -ENAMETOOLONG;
			break;
		}
		off += n - 1; // the next component overwrites the NUL
		if (!i) {
			if (off >= CGROUP_PATH_SIZE)
				s->p.len = -ENAMETOOLONG;
			else
				s->p.len = off + 1;
		}
	}
	bpf_map_update_elem(&cgroup_paths, &id, &s->p, BPF_NOEXIST);
	bpf_task_storage_delete(&cgroup_scratch, task);
	return id;
}

// Records the current process as the owner of a TCP or UDP socket it uses,
// and saves its record in exec_recent the first time it does. Saves the path
// of its cgroup on a connect, and on a send when the socket's cgroup changed.
static __always_inline void record_socket_user(struct socket *sock, int connect)
{
	struct sock *sk = sock->sk;
	struct sock_owner *so;
	struct exec_path *e;
	__u32 tgid;

	if (!sk ||
	    (sk->__sk_common.skc_family != AF_INET &&
	     sk->__sk_common.skc_family != AF_INET6) ||
	    !tracked_protocol(sk->sk_protocol))
		return;
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!so)
		return;
	record_current(so);
	if (connect || so->named_cgroup != so->cgroup_id) {
		__u64 id = save_cgroup_path(bpf_get_current_task_btf());

		// The task can move between reading its cgroup ID and its
		// path; only a path saved for the recorded ID counts.
		so->named_cgroup = id == so->cgroup_id ? id : 0;
	}
	tgid = so->owner.tgid;
	if (so->saved_tgid == tgid)
		return;
	e = bpf_task_storage_get(&exec_tasks,
				 bpf_get_current_task_btf()->group_leader, 0, 0);
	if (e && !bpf_map_update_elem(&exec_recent, &tgid, e, BPF_ANY))
		so->saved_tgid = tgid;
}

// Runs in the sending process for every send, write or splice on a socket,
// connected or not, before the data goes out. ret is the verdict of the BPF
// LSM programs that ran before this one, which must stand.
SEC("lsm/socket_sendmsg")
int BPF_PROG(record_send, struct socket *sock, struct msghdr *msg, int size,
	     int ret)
{
	if (ret)
		return ret;
	record_socket_user(sock, 0);
	return 0;
}

// A TCP connection's first packet leaves on connect, before any send.
SEC("lsm/socket_connect")
int BPF_PROG(record_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret)
		return ret;
	record_socket_user(sock, 1);
	return 0;
}

SEC("iter/task")
int seed_tasks(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	struct exec_path *e;
	__u32 zero = 0;

	if (!task || task->group_leader != task)
		return 0;
	// The hooks are already attached; what they recorded is newer.
	if (bpf_task_storage_get(&exec_tasks, task, 0, 0))
		return 0;
	// A task executing right now may not have its new record yet. Leave it
	// to record_exec, whose scratch also marks that window.
	if (bpf_task_storage_get(&exec_scratch, task, 0, 0))
		return 0;
	e = bpf_map_lookup_elem(&seed_scratch, &zero);
	if (!e)
		return 0;
	if (!record_exe_path(task, e)) // kernel thread, exited, or no executable
		return 0;
	e->start_ns = task->start_boottime;
	// record_exec may have started while the path was read; it updates the
	// storage once it completes, and its own retry covers the other order.
	if (bpf_task_storage_get(&exec_scratch, task, 0, 0))
		return 0;
	bpf_task_storage_get(&exec_tasks, task, e,
			     BPF_LOCAL_STORAGE_GET_F_CREATE);
	return 0;
}

char _license[] SEC("license") = "GPL";
