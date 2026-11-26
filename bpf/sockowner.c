// SPDX-License-Identifier: GPL-2.0-only

// Records which process owns each outgoing TCP/UDP flow, so that mihomo can
// match PROCESS-NAME and PROCESS-PATH rules after the socket has gone away and
// without scanning /proc. The owner's cgroup v2 ID goes in conn_cgroups, which
// lets mihomo name the systemd unit or Flatpak app behind a flow.
//
// The cgroup socket hooks run in the context of the process that creates,
// connects or sends on a socket and remember it in socket-local storage. The
// egress hook publishes the owner in conn_owners, keyed by network namespace,
// protocol, source address and source port, as taken from each outgoing
// packet, and in conn_flows, whose key adds the destination address and port.
// Sockets with different peers can share a source address and port, which
// only conn_flows tells apart. Entries outlive the socket and are evicted
// least-recently-used.
//
// Only UAPI context structures are used, so the object needs no BTF
// relocations. The programs avoid helpers that need CAP_PERFMON (such as
// bpf_get_current_comm), so loading needs only CAP_BPF and CAP_NET_ADMIN.
// Sends on a connected socket don't run the cgroup hooks; with -exec-paths,
// LSM programs in execpath.c record those.
//
// Build: go generate in the repository root, which needs clang and the libbpf headers.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "sockowner.h"

#define SOCK_STREAM 1
#define SOCK_DGRAM 2

struct conn_key {
	__u64 netns;
	__u8 addr[16]; // IPv4 is stored IPv4-mapped (::ffff:a.b.c.d)
	__u16 port;    // host byte order
	__u8 proto;    // IPPROTO_TCP or IPPROTO_UDP
	__u8 pad[5];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_owner);
} conn_owners SEC(".maps");

// The owner's cgroup for each key of conn_owners, published at the same time.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct conn_key);
	__type(value, struct conn_cgroup);
} conn_cgroups SEC(".maps");

// conn_flows adds the destination to conn_key, so that sockets sharing a local
// address and port are told apart, and holds the owner and its cgroup in one
// record, which no separate eviction can split.
struct flow_key {
	__u64 netns;
	__u8 saddr[16]; // IPv4 is stored IPv4-mapped (::ffff:a.b.c.d)
	__u8 daddr[16];
	__u16 sport;    // host byte order
	__u16 dport;    // host byte order
	__u8 proto;
	__u8 pad[3];
};

struct conn_flow {
	struct conn_owner owner;
	__u64 cgroup_id; // cgroup v2 ID of the owner, or 0
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct conn_flow);
} conn_flows SEC(".maps");

SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *sk)
{
	struct sock_owner *so;

	if ((sk->family != AF_INET && sk->family != AF_INET6) ||
	    !tracked_protocol(sk->protocol))
		return 1;
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (so) {
		record_current(so);
		so->netns = bpf_get_netns_cookie(sk);
	}
	return 1;
}

// connect and unconnected sendmsg run in the process that actually uses the
// socket, which may differ from its creator when the socket was inherited or
// passed over a UNIX socket. They also cover sockets created before the
// programs were attached. Sends on a connected socket skip the sendmsg hooks;
// record_send in execpath.c covers those.
static __always_inline int record_sock_addr(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	struct sock_owner *so;

	if (!sk || !tracked_protocol(sk->protocol))
		return 1;
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (so) {
		record_current(so);
		so->netns = bpf_get_netns_cookie(ctx);
	}
	return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *ctx)
{
	return record_sock_addr(ctx);
}

// Netfilter may change the source port when redirecting flows that would
// otherwise collide at the local listener, and a redirect changes the
// destination. The socket keeps its original ports, but readers see the
// translated packet's. Parse them just as we do the addresses, including IP
// options and IPv6 extension headers.
static __always_inline int packet_ports(struct __sk_buff *skb, __u8 version,
					__u8 protocol, __u16 *sport,
					__u16 *dport)
{
	__u32 offset;
	__u16 fragment, wire_ports[2];
	__u8 next;

	if (version == 4) {
		__u8 ihl;

		if (bpf_skb_load_bytes(skb, 0, &ihl, 1) ||
		    bpf_skb_load_bytes(skb, 6, &fragment, 2) ||
		    bpf_skb_load_bytes(skb, 9, &next, 1))
			return -1;
		offset = (ihl & 0x0f) * 4;
		if (offset < 20 || (bpf_ntohs(fragment) & 0x1fff))
			return -1;
	} else {
		if (bpf_skb_load_bytes(skb, 6, &next, 1))
			return -1;
		offset = 40;
		// Bound the walk for the verifier. Unknown protocols, noninitial
		// fragments and longer chains don't expose a usable TCP/UDP port.
		for (int i = 0; i < 8; i++) {
			__u8 header[2];

			if (tracked_protocol(next))
				break;
			if (bpf_skb_load_bytes(skb, offset, header, 2))
				return -1;
			switch (next) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
				offset += ((__u32)header[1] + 1) * 8;
				break;
			case IPPROTO_AH:
				offset += ((__u32)header[1] + 2) * 4;
				break;
			case IPPROTO_FRAGMENT:
				if (bpf_skb_load_bytes(skb, offset + 2, &fragment, 2) ||
				    (bpf_ntohs(fragment) & 0xfff8))
					return -1;
				offset += 8;
				break;
			default:
				return -1;
			}
			next = header[0];
		}
	}
	if (next != protocol ||
	    bpf_skb_load_bytes(skb, offset, wire_ports, sizeof(wire_ports)))
		return -1;
	*sport = bpf_ntohs(wire_ports[0]);
	*dport = bpf_ntohs(wire_ports[1]);
	return 0;
}

// Kernel-generated replies (RST for a closed port, ACK for a time-wait flow)
// leave from a per-CPU SOCK_RAW TCP control socket. It has no owning user
// process, so its packets must not replace an existing flow's owner.
static __always_inline int tracked_socket_type(__u32 type)
{
	return type == SOCK_STREAM || type == SOCK_DGRAM;
}

SEC("cgroup_skb/egress")
int egress(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;
	struct sock_owner *so;
	struct conn_key key = {};
	struct flow_key fkey = {};
	__u8 version;

	if (!sk)
		return 1;
	sk = bpf_sk_fullsock(sk);
	if (!sk || !tracked_socket_type(sk->type) ||
	    !tracked_protocol(sk->protocol))
		return 1;
	// Sockets that existed before the programs were attached and accepted
	// sockets have no owner. They still publish an empty owner, so that a
	// stale entry for the same address and port is not mistaken for theirs.
	// MPTCP's TCP subflows are kernel sockets that also have no owner; as we
	// can't reach the MPTCP socket's owner from here without CAP_PERFMON,
	// they publish unknown (TGID 0) too, rather than a stale owner.
	so = bpf_sk_storage_get(&sock_owners, sk, 0,
				BPF_SK_STORAGE_GET_F_CREATE);
	if (!so)
		return 1;
	if (!so->netns)
		so->netns = bpf_get_netns_cookie(skb);

	// The socket may be bound to a wildcard address, so take the source
	// address from the packet. Egress data starts at the network header.
	if (bpf_skb_load_bytes(skb, 0, &version, 1))
		return 1;
	version >>= 4;
	if (version == 4) {
		fkey.saddr[10] = fkey.saddr[11] = 0xff;
		fkey.daddr[10] = fkey.daddr[11] = 0xff;
		if (bpf_skb_load_bytes(skb, 12, &fkey.saddr[12], 4) ||
		    bpf_skb_load_bytes(skb, 16, &fkey.daddr[12], 4))
			return 1;
	} else if (version == 6) {
		if (bpf_skb_load_bytes(skb, 8, fkey.saddr, 16) ||
		    bpf_skb_load_bytes(skb, 24, fkey.daddr, 16))
			return 1;
	} else {
		return 1;
	}

	fkey.netns = so->netns;
	fkey.proto = sk->protocol;
	if (packet_ports(skb, version, fkey.proto, &fkey.sport, &fkey.dport))
		return 1;
	key.netns = fkey.netns;
	__builtin_memcpy(key.addr, fkey.saddr, sizeof(key.addr));
	key.port = fkey.sport;
	key.proto = fkey.proto;

	// Snapshot owner and cgroup together so concurrent sends on a shared
	// socket cannot publish a torn pair across the three maps.
	struct conn_owner owner;
	__u64 cgroup_id;

	bpf_spin_lock(&so->lock);
	owner = so->owner;
	cgroup_id = so->cgroup_id;
	bpf_spin_unlock(&so->lock);

	// Check the maps on every packet rather than remembering what this
	// socket published: the source address and port can change (a UDP
	// socket that disconnects is bound again on its next send), and the
	// entries may have been evicted, each map on its own. The lookups also
	// keep the entries of an active flow recently used.
	struct conn_owner *published = bpf_map_lookup_elem(&conn_owners, &key);
	if (!published ||
	    __builtin_memcmp(published, &owner, sizeof(owner)))
		bpf_map_update_elem(&conn_owners, &key, &owner, BPF_ANY);

	// An unowned socket publishes an empty record here too, so a stale
	// cgroup is never taken for its own.
	struct conn_cgroup cg = {
		.tgid = owner.tgid,
		.boot_ns = owner.boot_ns,
		.cgroup_id = owner.tgid ? cgroup_id : 0,
	};
	struct conn_cgroup *cg_published = bpf_map_lookup_elem(&conn_cgroups, &key);
	if (!cg_published || __builtin_memcmp(cg_published, &cg, sizeof(cg)))
		bpf_map_update_elem(&conn_cgroups, &key, &cg, BPF_ANY);

	struct conn_flow flow = {
		.owner = owner,
		.cgroup_id = cg.cgroup_id,
	};
	struct conn_flow *flow_published = bpf_map_lookup_elem(&conn_flows, &fkey);
	if (!flow_published ||
	    __builtin_memcmp(flow_published, &flow, sizeof(flow)))
		bpf_map_update_elem(&conn_flows, &fkey, &flow, BPF_ANY);
	return 1;
}

char _license[] SEC("license") = "GPL";
