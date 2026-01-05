#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/version.h>

#include "../klog.h" // IWYU pragma: keep
#include "selinux.h"
#include "sepolicy.h"
#include "ss/services.h"
#include "linux/lsm_audit.h" // IWYU pragma: keep
#include "xfrm.h"

#define SELINUX_POLICY_INSTEAD_SELINUX_SS

#define ALL NULL

static struct policydb *get_policydb(void)
{
    struct policydb *db;
    struct selinux_policy *policy = selinux_state.policy;
    db = &policy->policydb;
    return db;
}

static DEFINE_MUTEX(ksu_rules);

void apply_kernelsu_rules()
{
    struct policydb *db;

    if (!getenforce()) {
        pr_info("SELinux permissive or disabled, apply rules!\n");
    }

    mutex_lock(&ksu_rules);

    db = get_policydb();

    ksu_permissive(db, KERNEL_SU_DOMAIN);
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "mlstrustedsubject");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "netdomain");
    ksu_typeattribute(db, KERNEL_SU_DOMAIN, "bluetoothdomain");

    // Create unconstrained file type
    ksu_type(db, KERNEL_SU_FILE, "file_type");
    ksu_typeattribute(db, KERNEL_SU_FILE, "mlstrustedobject");
    ksu_allow(db, ALL, KERNEL_SU_FILE, ALL, ALL);

    // allow all!
    ksu_allow(db, KERNEL_SU_DOMAIN, ALL, ALL, ALL);

    // allow us do any ioctl
    if (db->policyvers >= POLICYDB_VERSION_XPERMS_IOCTL) {
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "blk_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "fifo_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "chr_file", ALL);
        ksu_allowxperm(db, KERNEL_SU_DOMAIN, ALL, "file", ALL);
    }

    // ================ 关键修复：解决init访问/data/adb权限问题 ================
    
    // 修复：允许 init 搜索 adb_data_file 目录（对应 /data/adb/）
    ksu_allow(db, "init", "adb_data_file", "dir", "search");
    ksu_allow(db, "init", "adb_data_file", "dir", "open");
    ksu_allow(db, "init", "adb_data_file", "dir", "read");
    ksu_allow(db, "init", "adb_data_file", "dir", "getattr");
    ksu_allow(db, "init", "adb_data_file", "dir", "write");
    ksu_allow(db, "init", "adb_data_file", "dir", "add_name");
    ksu_allow(db, "init", "adb_data_file", "dir", "remove_name");
    ksu_allow(db, "init", "adb_data_file", "dir", "reparent");
    ksu_allow(db, "init", "adb_data_file", "dir", "setattr");
    ksu_allow(db, "init", "adb_data_file", "dir", "create");
    
    // 修复：允许 init 执行 adb_data_file 类型的文件（对应 /data/adb/ksud）
    ksu_allow(db, "init", "adb_data_file", "file", "execute");
    ksu_allow(db, "init", "adb_data_file", "file", "execute_no_trans");
    ksu_allow(db, "init", "adb_data_file", "file", "open");
    ksu_allow(db, "init", "adb_data_file", "file", "read");
    ksu_allow(db, "init", "adb_data_file", "file", "getattr");
    ksu_allow(db, "init", "adb_data_file", "file", "entrypoint");
    ksu_allow(db, "init", "adb_data_file", "file", "write");
    ksu_allow(db, "init", "adb_data_file", "file", "create");
    ksu_allow(db, "init", "adb_data_file", "file", "setattr");
    ksu_allow(db, "init", "adb_data_file", "file", "unlink");
    ksu_allow(db, "init", "adb_data_file", "file", "rename");
    ksu_allow(db, "init", "adb_data_file", "file", "append");
    ksu_allow(db, "init", "adb_data_file", "file", "lock");
    
    // 修复：允许 init 转换到 su 域
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, "process", "transition");
    ksu_type_transition(db, "init", "adb_data_file", "process", KERNEL_SU_DOMAIN,NULL);
    
    // 修复：允许 init 创建和管理 su 进程
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, "process", "fork");
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, "process", "sigchld");
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, "process", "rlimitinh");
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, "process", "siginh");
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, "process", "noatsecure");
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, "process", "dyntransition");
    
    // 修复：允许 su 域完全访问 adb_data_file
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "dir", ALL);
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "file", ALL);

    // ================ 新问题修复：shell域访问adb_data_file ================
    
    // 修复：允许 shell 域访问 adb_data_file 目录（对应 /data/adb/）
    // 日志错误：avc: denied { getattr } for path="/data/adb" scontext=u:r:shell:s0
    ksu_allow(db, "shell", "adb_data_file", "dir", "getattr");
    ksu_allow(db, "shell", "adb_data_file", "dir", "search");
    ksu_allow(db, "shell", "adb_data_file", "dir", "open");
    ksu_allow(db, "shell", "adb_data_file", "dir", "read");
    ksu_allow(db, "shell", "adb_data_file", "dir", "write");
    ksu_allow(db, "shell", "adb_data_file", "dir", "add_name");
    ksu_allow(db, "shell", "adb_data_file", "dir", "remove_name");
    ksu_allow(db, "shell", "adb_data_file", "dir", "setattr");
    ksu_allow(db, "shell", "adb_data_file", "dir", "create");
    
    // 修复：允许 shell 域访问 adb_data_file 文件
    ksu_allow(db, "shell", "adb_data_file", "file", "getattr");
    ksu_allow(db, "shell", "adb_data_file", "file", "open");
    ksu_allow(db, "shell", "adb_data_file", "file", "read");
    ksu_allow(db, "shell", "adb_data_file", "file", "write");
    ksu_allow(db, "shell", "adb_data_file", "file", "create");
    ksu_allow(db, "shell", "adb_data_file", "file", "setattr");
    ksu_allow(db, "shell", "adb_data_file", "file", "unlink");
    ksu_allow(db, "shell", "adb_data_file", "file", "rename");
    ksu_allow(db, "shell", "adb_data_file", "file", "execute");
    ksu_allow(db, "shell", "adb_data_file", "file", "execute_no_trans");
    
    // ================ 修复：确保 /data/adb/ 目录可以被正确访问 ================
    
    // 允许 su 域对 /data/adb/ 目录有完全控制权限
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "filesystem", "mount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "filesystem", "unmount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "filesystem", "remount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "filesystem", "associate");
    
    

    // 允许 su 域管理 adb_data_file 类型的安全上下文
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "dir", "relabelfrom");
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "dir", "relabelto");
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "file", "relabelfrom");
    ksu_allow(db, KERNEL_SU_DOMAIN, "adb_data_file", "file", "relabelto");
    
    // ================ 修复：文件系统访问权限 ================
    
    // 允许 su 域访问 data_file_type（/data 分区）
    ksu_allow(db, KERNEL_SU_DOMAIN, "data_file_type", "filesystem", "mount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "data_file_type", "filesystem", "unmount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "data_file_type", "filesystem", "remount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "data_file_type", "filesystem", "associate");
    
    // 允许 su 域访问 rootfs（根文件系统）
    ksu_allow(db, KERNEL_SU_DOMAIN, "rootfs", "filesystem", "mount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "rootfs", "filesystem", "unmount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "rootfs", "filesystem", "remount");
    ksu_allow(db, KERNEL_SU_DOMAIN, "rootfs", "filesystem", "associate");
    
    //修复：init 对文件系统的访问 ================
    
    ksu_allow(db, "init", "data_file_type", "filesystem", "mount");
    ksu_allow(db, "init", "data_file_type", "filesystem", "unmount");
    ksu_allow(db, "init", "data_file_type", "filesystem", "remount");
    ksu_allow(db, "init", "data_file_type", "filesystem", "associate");
    ksu_allow(db, "init", "rootfs", "filesystem", "mount");
    ksu_allow(db, "init", "rootfs", "filesystem", "unmount");
    ksu_allow(db, "init", "rootfs", "filesystem", "remount");
    ksu_allow(db, "init", "rootfs", "filesystem", "associate");
    
    // ================ 新问题修复：untrusted_app访问shell_test_data_file ================
    
    // 修复：允许 untrusted_app 搜索 shell_test_data_file 目录
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "dir", "search");
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "dir", "open");
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "dir", "read");
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "dir", "getattr");
    // 加在你原来的app_data_file规则后面，完整放行
ksu_allow(db, KERNEL_SU_DOMAIN, "app_data_file", "dir", ALL);
ksu_allow(db, KERNEL_SU_DOMAIN, "app_data_file", "file", ALL);
ksu_allow(db, KERNEL_SU_DOMAIN, "app_lib_file", "file", ALL); // 关键！lib目录专属标签

    
    // 修复：允许 untrusted_app 访问 shell_test_data_file 文件
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "file", "read");
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "file", "open");
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "file", "getattr");
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "file", "execute");
    ksu_allow(db, "untrusted_app", "shell_test_data_file", "file", "execute_no_trans");

    // ================ 修复：创建shell进程相关权限 ================
    
    // 允许 untrusted_app 转换到 shell 域（用于创建shell）
    ksu_allow(db, "untrusted_app", "shell", "process", "transition");
    ksu_allow(db, "untrusted_app", "shell", "process", "dyntransition");
    
    // 允许 untrusted_app 执行 shell_exec 类型的文件
    ksu_allow(db, "untrusted_app", "shell_exec", "file", "execute");
    ksu_allow(db, "untrusted_app", "shell_exec", "file", "execute_no_trans");
    ksu_allow(db, "untrusted_app", "shell_exec", "file", "open");
    ksu_allow(db, "untrusted_app", "shell_exec", "file", "read");
    ksu_allow(db, "untrusted_app", "shell_exec", "file", "getattr");
    
    // 定义 untrusted_app 执行 shell_exec 类型文件时转换到 shell 域
    ksu_type_transition(db, "untrusted_app", "shell_exec", "process", "shell",NULL);
    
    // 允许 shell 域访问各种资源
    ksu_allow(db, "shell", "untrusted_app", "fd", "use");
    ksu_allow(db, "shell", "untrusted_app", "fifo_file", "write");
    ksu_allow(db, "shell", "untrusted_app", "fifo_file", "read");
    ksu_allow(db, "shell", "untrusted_app", "fifo_file", "open");
    ksu_allow(db, "shell", "untrusted_app", "fifo_file", "getattr");
    
    // 允许 untrusted_app 与 shell 进程通信
    ksu_allow(db, "untrusted_app", "shell", "process", "sigchld");
    ksu_allow(db, "untrusted_app", "shell", "process", "sigkill");
    ksu_allow(db, "untrusted_app", "shell", "process", "signal");
    ksu_allow(db, "untrusted_app", "shell", "process", "getattr");
    ksu_allow(db, "untrusted_app", "shell", "process", "getpgid");

    // ================ 允许 KERNEL_SU_DOMAIN 创建和管理 shell 进程 ================
    
    ksu_allow(db, KERNEL_SU_DOMAIN, "shell", "process", "transition");
    ksu_allow(db, KERNEL_SU_DOMAIN, "shell", "process", "fork");
    ksu_allow(db, KERNEL_SU_DOMAIN, "shell", "process", "sigchld");
    ksu_allow(db, KERNEL_SU_DOMAIN, "shell_exec", "file", "execute");
    ksu_type_transition(db, KERNEL_SU_DOMAIN, "shell_exec", "process", "shell",NULL);

    // ================ 原有规则 ================
    
    // our ksud triggered by init
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);

    // copied from Magisk rules
    // suRights
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "dir", "read");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "servicemanager", KERNEL_SU_DOMAIN, "process", "getattr");
    ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "process", "sigchld");

    // allowLog
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "logd", KERNEL_SU_DOMAIN, "file", "getattr");

    // dumpsys
    ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fd", "use");
    ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "write");
    ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "read");
    ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "open");
    ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "fifo_file", "getattr");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "dir", "search");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "read");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "file", "open");
    ksu_allow(db, "hwservicemanager", KERNEL_SU_DOMAIN, "process", "getattr");

    // Allow all binder transactions
    ksu_allow(db, ALL, KERNEL_SU_DOMAIN, "binder", ALL);

    // Allow system server kill su process
    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "getpgid");
    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

    mutex_unlock(&ksu_rules);
}
    
    
#define MAX_SEPOL_LEN 128

#define CMD_NORMAL_PERM 1
#define CMD_XPERM 2
#define CMD_TYPE_STATE 3
#define CMD_TYPE 4
#define CMD_TYPE_ATTR 5
#define CMD_ATTR 6
#define CMD_TYPE_TRANSITION 7
#define CMD_TYPE_CHANGE 8
#define CMD_GENFSCON 9

struct sepol_data {
    u32 cmd;
    u32 subcmd;
    char __user *sepol1;
    char __user *sepol2;
    char __user *sepol3;
    char __user *sepol4;
    char __user *sepol5;
    char __user *sepol6;
    char __user *sepol7;
};

static int get_object(char *buf, char __user *user_object, size_t buf_sz,
                      char **object)
{
    if (!user_object) {
        *object = ALL;
        return 0;
    }

    if (strncpy_from_user(buf, user_object, buf_sz) < 0) {
        return -EINVAL;
    }

    *object = buf;

    return 0;
}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
extern int avc_ss_reset(u32 seqno);
#else
extern int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
#endif
// reset avc cache table, otherwise the new rules will not take effect if already denied
static void reset_avc_cache()
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
    avc_ss_reset(0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(0);
#else
    struct selinux_avc *avc = selinux_state.avc;
    avc_ss_reset(avc, 0);
    selnl_notify_policyload(0);
    selinux_status_update_policyload(&selinux_state, 0);
#endif
    selinux_xfrm_notify_policyload();
}

int handle_sepolicy(unsigned long arg3, void __user *arg4)
{
    struct policydb *db;

    if (!arg4) {
        return -EINVAL;
    }

    if (!getenforce()) {
        pr_info("SELinux permissive or disabled when handle policy!\n");
    }

    struct sepol_data data;
    if (copy_from_user(&data, arg4, sizeof(struct sepol_data))) {
        pr_err("sepol: copy sepol_data failed.\n");
        return -EINVAL;
    }

    u32 cmd = data.cmd;
    u32 subcmd = data.subcmd;

    mutex_lock(&ksu_rules);

    db = get_policydb();

    int ret = -EINVAL;
    if (cmd == CMD_NORMAL_PERM) {
        char src_buf[MAX_SEPOL_LEN];
        char tgt_buf[MAX_SEPOL_LEN];
        char cls_buf[MAX_SEPOL_LEN];
        char perm_buf[MAX_SEPOL_LEN];

        char *s, *t, *c, *p;
        if (get_object(src_buf, data.sepol1, sizeof(src_buf), &s) < 0) {
            pr_err("sepol: copy src failed.\n");
            goto exit;
        }

        if (get_object(tgt_buf, data.sepol2, sizeof(tgt_buf), &t) < 0) {
            pr_err("sepol: copy tgt failed.\n");
            goto exit;
        }

        if (get_object(cls_buf, data.sepol3, sizeof(cls_buf), &c) < 0) {
            pr_err("sepol: copy cls failed.\n");
            goto exit;
        }

        if (get_object(perm_buf, data.sepol4, sizeof(perm_buf), &p) < 0) {
            pr_err("sepol: copy perm failed.\n");
            goto exit;
        }

        bool success = false;
        if (subcmd == 1) {
            success = ksu_allow(db, s, t, c, p);
        } else if (subcmd == 2) {
            success = ksu_deny(db, s, t, c, p);
        } else if (subcmd == 3) {
            success = ksu_auditallow(db, s, t, c, p);
        } else if (subcmd == 4) {
            success = ksu_dontaudit(db, s, t, c, p);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", subcmd);
        }
        ret = success ? 0 : -EINVAL;

    } else if (cmd == CMD_XPERM) {
        char src_buf[MAX_SEPOL_LEN];
        char tgt_buf[MAX_SEPOL_LEN];
        char cls_buf[MAX_SEPOL_LEN];

        char __maybe_unused operation[MAX_SEPOL_LEN]; // it is always ioctl now!
        char perm_set[MAX_SEPOL_LEN];

        char *s, *t, *c;
        if (get_object(src_buf, data.sepol1, sizeof(src_buf), &s) < 0) {
            pr_err("sepol: copy src failed.\n");
            goto exit;
        }
        if (get_object(tgt_buf, data.sepol2, sizeof(tgt_buf), &t) < 0) {
            pr_err("sepol: copy tgt failed.\n");
            goto exit;
        }
        if (get_object(cls_buf, data.sepol3, sizeof(cls_buf), &c) < 0) {
            pr_err("sepol: copy cls failed.\n");
            goto exit;
        }
        if (strncpy_from_user(operation, data.sepol4, sizeof(operation)) < 0) {
            pr_err("sepol: copy operation failed.\n");
            goto exit;
        }
        if (strncpy_from_user(perm_set, data.sepol5, sizeof(perm_set)) < 0) {
            pr_err("sepol: copy perm_set failed.\n");
            goto exit;
        }

        bool success = false;
        if (subcmd == 1) {
            success = ksu_allowxperm(db, s, t, c, perm_set);
        } else if (subcmd == 2) {
            success = ksu_auditallowxperm(db, s, t, c, perm_set);
        } else if (subcmd == 3) {
            success = ksu_dontauditxperm(db, s, t, c, perm_set);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", subcmd);
        }
        ret = success ? 0 : -EINVAL;
    } else if (cmd == CMD_TYPE_STATE) {
        char src[MAX_SEPOL_LEN];

        if (strncpy_from_user(src, data.sepol1, sizeof(src)) < 0) {
            pr_err("sepol: copy src failed.\n");
            goto exit;
        }

        bool success = false;
        if (subcmd == 1) {
            success = ksu_permissive(db, src);
        } else if (subcmd == 2) {
            success = ksu_enforce(db, src);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", subcmd);
        }
        if (success)
            ret = 0;

    } else if (cmd == CMD_TYPE || cmd == CMD_TYPE_ATTR) {
        char type[MAX_SEPOL_LEN];
        char attr[MAX_SEPOL_LEN];

        if (strncpy_from_user(type, data.sepol1, sizeof(type)) < 0) {
            pr_err("sepol: copy type failed.\n");
            goto exit;
        }
        if (strncpy_from_user(attr, data.sepol2, sizeof(attr)) < 0) {
            pr_err("sepol: copy attr failed.\n");
            goto exit;
        }

        bool success = false;
        if (cmd == CMD_TYPE) {
            success = ksu_type(db, type, attr);
        } else {
            success = ksu_typeattribute(db, type, attr);
        }
        if (!success) {
            pr_err("sepol: %d failed.\n", cmd);
            goto exit;
        }
        ret = 0;

    } else if (cmd == CMD_ATTR) {
        char attr[MAX_SEPOL_LEN];

        if (strncpy_from_user(attr, data.sepol1, sizeof(attr)) < 0) {
            pr_err("sepol: copy attr failed.\n");
            goto exit;
        }
        if (!ksu_attribute(db, attr)) {
            pr_err("sepol: %d failed.\n", cmd);
            goto exit;
        }
        ret = 0;

    } else if (cmd == CMD_TYPE_TRANSITION) {
        char src[MAX_SEPOL_LEN];
        char tgt[MAX_SEPOL_LEN];
        char cls[MAX_SEPOL_LEN];
        char default_type[MAX_SEPOL_LEN];
        char object[MAX_SEPOL_LEN];

        if (strncpy_from_user(src, data.sepol1, sizeof(src)) < 0) {
            pr_err("sepol: copy src failed.\n");
            goto exit;
        }
        if (strncpy_from_user(tgt, data.sepol2, sizeof(tgt)) < 0) {
            pr_err("sepol: copy tgt failed.\n");
            goto exit;
        }
        if (strncpy_from_user(cls, data.sepol3, sizeof(cls)) < 0) {
            pr_err("sepol: copy cls failed.\n");
            goto exit;
        }
        if (strncpy_from_user(default_type, data.sepol4, sizeof(default_type)) <
            0) {
            pr_err("sepol: copy default_type failed.\n");
            goto exit;
        }
        char *real_object;
        if (data.sepol5 == NULL) {
            real_object = NULL;
        } else {
            if (strncpy_from_user(object, data.sepol5, sizeof(object)) < 0) {
                pr_err("sepol: copy object failed.\n");
                goto exit;
            }
            real_object = object;
        }

        bool success =
            ksu_type_transition(db, src, tgt, cls, default_type, real_object);
        if (success)
            ret = 0;

    } else if (cmd == CMD_TYPE_CHANGE) {
        char src[MAX_SEPOL_LEN];
        char tgt[MAX_SEPOL_LEN];
        char cls[MAX_SEPOL_LEN];
        char default_type[MAX_SEPOL_LEN];

        if (strncpy_from_user(src, data.sepol1, sizeof(src)) < 0) {
            pr_err("sepol: copy src failed.\n");
            goto exit;
        }
        if (strncpy_from_user(tgt, data.sepol2, sizeof(tgt)) < 0) {
            pr_err("sepol: copy tgt failed.\n");
            goto exit;
        }
        if (strncpy_from_user(cls, data.sepol3, sizeof(cls)) < 0) {
            pr_err("sepol: copy cls failed.\n");
            goto exit;
        }
        if (strncpy_from_user(default_type, data.sepol4, sizeof(default_type)) <
            0) {
            pr_err("sepol: copy default_type failed.\n");
            goto exit;
        }
        bool success = false;
        if (subcmd == 1) {
            success = ksu_type_change(db, src, tgt, cls, default_type);
        } else if (subcmd == 2) {
            success = ksu_type_member(db, src, tgt, cls, default_type);
        } else {
            pr_err("sepol: unknown subcmd: %d\n", subcmd);
        }
        if (success)
            ret = 0;
    } else if (cmd == CMD_GENFSCON) {
        char name[MAX_SEPOL_LEN];
        char path[MAX_SEPOL_LEN];
        char context[MAX_SEPOL_LEN];
        if (strncpy_from_user(name, data.sepol1, sizeof(name)) < 0) {
            pr_err("sepol: copy name failed.\n");
            goto exit;
        }
        if (strncpy_from_user(path, data.sepol2, sizeof(path)) < 0) {
            pr_err("sepol: copy path failed.\n");
            goto exit;
        }
        if (strncpy_from_user(context, data.sepol3, sizeof(context)) < 0) {
            pr_err("sepol: copy context failed.\n");
            goto exit;
        }

        if (!ksu_genfscon(db, name, path, context)) {
            pr_err("sepol: %d failed.\n", cmd);
            goto exit;
        }
        ret = 0;
    } else {
        pr_err("sepol: unknown cmd: %d\n", cmd);
    }

exit:
    mutex_unlock(&ksu_rules);

    // only allow and xallow needs to reset avc cache, but we cannot do that because
    // we are in atomic context. so we just reset it every time.
    reset_avc_cache();

    return ret;
}
