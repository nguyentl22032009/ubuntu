#ifndef HIDING_STAT_H
#define HIDING_STAT_H

#include <linux/types.h>
#include <linux/fs.h>

bool should_hide_path(const char __user *pathname);
int hiding_stat_init(void);
void hiding_stat_exit(void);

#endif