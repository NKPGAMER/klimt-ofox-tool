/*
 * Stub SCP module for TWRP recovery
 * Provides symbols needed by goodix_core_dali.ko without initializing hardware
 */
#include <linux/module.h>
#include <linux/kernel.h>

/* Stub functions for SCP symbols needed by goodix_core_dali.ko */
void *scp_ipidev = NULL;
EXPORT_SYMBOL(scp_ipidev);

phys_addr_t scp_get_reserve_mem_phys(int id) {
    return 0;
}
EXPORT_SYMBOL(scp_get_reserve_mem_phys);

void *scp_get_reserve_mem_virt(int id) {
    return NULL;
}
EXPORT_SYMBOL(scp_get_reserve_mem_virt);

size_t scp_get_reserve_mem_size(int id) {
    return 0;
}
EXPORT_SYMBOL(scp_get_reserve_mem_size);

int scp_A_register_notify(struct notifier_block *nb) {
    return 0;
}
EXPORT_SYMBOL(scp_A_register_notify);

int scp_A_unregister_notify(struct notifier_block *nb) {
    return 0;
}
EXPORT_SYMBOL(scp_A_unregister_notify);

static int __init scp_stub_init(void) {
    pr_info("scp_stub: loaded (stub mode for TWRP)\n");
    return 0;
}

static void __exit scp_stub_exit(void) {
    pr_info("scp_stub: unloaded\n");
}

module_init(scp_stub_init);
module_exit(scp_stub_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SCP stub module for TWRP recovery");
