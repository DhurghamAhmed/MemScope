#include <stdint.h>

void *g_anchor_root = (void *)(uintptr_t)0xA1A1A1A1u;

unsigned long long g_anchor_guard_before = 0xFEEDFACEDEADBEEFull;
unsigned long long g_anchor_guard_after = 0xDEADBEEFCAFEBABEull;

void anchor_set_root(void *p)
{
    g_anchor_root = p;
}

void **anchor_root_address(void)
{
    return &g_anchor_root;
}
