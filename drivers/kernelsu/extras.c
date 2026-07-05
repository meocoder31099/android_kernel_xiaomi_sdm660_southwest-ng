#include <linux/security.h>
#include <linux/atomic.h>
#include <linux/version.h>

#include "policy/feature.h"
#include "uapi/feature.h"
#include "klog.h"
#include "runtime/ksud.h"
#include "infra/seccomp_cache.h"

// sorry for the ifdef hell
// but im too lazy to fragment this out.
// theres only one feature so far anyway
// - xx, 20251019

static u32 su_sid = 0;
static u32 priv_app_sid = 0;

// init as disabled by default
static atomic_t disable_spoof = ATOMIC_INIT(1);

void ksu_avc_spoof_enable();
void ksu_avc_spoof_disable();

static bool ksu_avc_spoof_enabled = true;
static bool boot_completed = false;

static int avc_spoof_feature_get(u64 *value)
{
	*value = ksu_avc_spoof_enabled ? 1 : 0;
	return 0;
}

static int avc_spoof_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_avc_spoof_enabled) {
#ifdef CONFIG_KSU_PRINT_INFO
		pr_info("avc_spoof: no need to change\n");
#endif
		return 0;
	}

	ksu_avc_spoof_enabled = enable;

	if (boot_completed) {
		if (enable) {
			ksu_avc_spoof_enable();
		} else {
			ksu_avc_spoof_disable();
		}
	}

#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("avc_spoof: set to %d\n", enable);
#endif

	return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
	.feature_id = KSU_FEATURE_AVC_SPOOF,
	.name = "avc_spoof",
	.get_handler = avc_spoof_feature_get,
	.set_handler = avc_spoof_feature_set,
};

static int get_sid()
{
	// dont load at all if we cant get sids
	int err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"), &su_sid);
	if (err) {
#ifdef CONFIG_KSU_PRINT_INFO
		pr_info("avc_spoof/get_sid: su_sid not found!\n");
#endif
		return -1;
	}
#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("avc_spoof/get_sid: su_sid: %u\n", su_sid);
#endif

	err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (err) {
#ifdef CONFIG_KSU_PRINT_INFO
		pr_info("avc_spoof/get_sid: priv_app_sid not found!\n");
#endif
		return -1;
	}
#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("avc_spoof/get_sid: priv_app_sid: %u\n", priv_app_sid);
#endif
	return 0;
}

int ksu_handle_slow_avc_audit(u32 *tsid)
{
	if (atomic_read(&disable_spoof))
		return 0;

	// if tsid is su, we just replace it
	// unsure if its enough, but this is how it is aye?
	if (*tsid == su_sid) {
#ifdef CONFIG_KSU_PRINT_INFO
		pr_info("avc_spoof/slow_avc_audit: replacing su_sid: %u with priv_app_sid: %u\n", su_sid, priv_app_sid);
#endif
		*tsid = priv_app_sid;
	}

	return 0;
}

#ifdef KSU_KPROBES_HOOK
#include <linux/kprobes.h>
#include <linux/slab.h>
#include "arch.h"
static struct kprobe *slow_avc_audit_kp;
//	.symbol_name = "slow_avc_audit",
//	.pre_handler = slow_avc_audit_pre_handler,
static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	if (atomic_read(&disable_spoof))
		return 0;

	/* 
	 * for < 4.17 int slow_avc_audit(u32 ssid, u32 tsid
	 * for >= 4.17 int slow_avc_audit(struct selinux_state *state, u32 ssid, u32 tsid
	 * for >= 6.4 int slow_avc_audit(u32 ssid, u32 tsid
	 * not to mention theres also DKSU_HAS_SELINUX_STATE
	 * since its hard to make sure this selinux state thing 
	 * cross crossing with 4.17 ~ 6.4's where slow_avc_audit
	 * changes abi (tsid in arg2 vs arg3)
	 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
	ksu_handle_slow_avc_audit(tsid);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
	ksu_handle_slow_avc_audit(tsid);
#endif

	return 0;
}

// copied from upstream
static struct kprobe *init_kprobe(const char *name,
				  kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return NULL;
	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("sucompat: register_%s kprobe: %d\n", name, ret);
#endif
	if (ret) {
		kfree(kp);
		return NULL;
	}

	return kp;
}
static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;
	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}
#endif // KSU_KPROBES_HOOK

void ksu_avc_spoof_disable(void)
{
#ifdef KSU_KPROBES_HOOK
#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("avc_spoof/exit: unregister slow_avc_audit kprobe!\n");
#endif
	destroy_kprobe(&slow_avc_audit_kp);
#endif
	atomic_set(&disable_spoof, 1);
#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("avc_spoof/exit: slow_avc_audit spoofing disabled!\n");
#endif
}

void ksu_avc_spoof_enable(void) 
{
	int ret = get_sid();
	if (ret) {
#ifdef CONFIG_KSU_PRINT_INFO
		pr_info("avc_spoof/init: sid grab fail!\n");
#endif
		return;
	}

#ifdef KSU_KPROBES_HOOK
#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("avc_spoof/init: register slow_avc_audit kprobe!\n");
#endif
	slow_avc_audit_kp = init_kprobe("slow_avc_audit", slow_avc_audit_pre_handler);
#endif	
	// once we get the sids, we can now enable the hook handler
	atomic_set(&disable_spoof, 0);
	
#ifdef CONFIG_KSU_PRINT_INFO
	pr_info("avc_spoof/init: slow_avc_audit spoofing enabled!\n");
#endif
}

void ksu_avc_spoof_late_init(void)
{
	boot_completed = true;
	
    if (ksu_avc_spoof_enabled) {
		ksu_avc_spoof_enable();
	}
}

void __init ksu_avc_spoof_init(void)
{
	if (ksu_register_feature_handler(&avc_spoof_handler)) {
		pr_err("Failed to register avc spoof feature handler\n");
	}
}

void __exit ksu_avc_spoof_exit(void)
{
	if (ksu_avc_spoof_enabled) {
		ksu_avc_spoof_disable();
	}
	ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
