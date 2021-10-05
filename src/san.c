#include "jemalloc/internal/jemalloc_preamble.h"
#include "jemalloc/internal/jemalloc_internal_includes.h"

#include "jemalloc/internal/assert.h"
#include "jemalloc/internal/ehooks.h"
#include "jemalloc/internal/san.h"
#include "jemalloc/internal/tsd.h"

/* The sanitizer options. */
size_t opt_san_guard_large = SAN_GUARD_LARGE_EVERY_N_EXTENTS_DEFAULT;
size_t opt_san_guard_small = SAN_GUARD_SMALL_EVERY_N_EXTENTS_DEFAULT;

static inline void
san_find_guarded_addr(edata_t *edata, uintptr_t *guard1, uintptr_t *guard2,
    uintptr_t *addr, size_t size, bool left, bool right) {
	*addr = (uintptr_t)edata_base_get(edata);
	if (left) {
		*guard1 = *addr;
		*addr += SAN_PAGE_GUARD;
	} else {
		*guard1 = 0;
	}

	if (right) {
		*guard2 = *addr + size;
	} else {
		*guard2 = 0;
	}
}

static inline void
san_find_unguarded_addr(edata_t *edata, uintptr_t *guard1, uintptr_t *guard2,
    uintptr_t *addr, size_t size, bool left, bool right) {
	*addr = (uintptr_t)edata_base_get(edata);
	if (right) {
		*guard2 = *addr + size;
	} else {
		*guard2 = 0;
	}

	if (left) {
		*guard1 = *addr - SAN_PAGE_GUARD;
		*addr = *guard1;
	} else {
		*guard1 = 0;
	}
}

void
san_guard_pages(tsdn_t *tsdn, ehooks_t *ehooks, edata_t *edata, emap_t *emap,
    bool left, bool right, bool reg_emap) {
	assert(left || right);
	emap_deregister_boundary(tsdn, emap, edata);

	size_t size_with_guards = edata_size_get(edata);
	size_t usize = (left && right)
	    ? san_two_side_unguarded_sz(size_with_guards)
	    : san_one_side_unguarded_sz(size_with_guards);

	uintptr_t guard1, guard2, addr;
	san_find_guarded_addr(edata, &guard1, &guard2, &addr, usize, left,
	    right);

	assert(edata_state_get(edata) == extent_state_active);
	ehooks_guard(tsdn, ehooks, (void *)guard1, (void *)guard2);

	/* Update the guarded addr and usable size of the edata. */
	edata_size_set(edata, usize);
	edata_addr_set(edata, (void *)addr);
	edata_guarded_set(edata, true);

	if (reg_emap) {
		emap_register_boundary(tsdn, emap, edata, SC_NSIZES,
		    /* slab */ false);
	}
}

void
san_unguard_pages(tsdn_t *tsdn, ehooks_t *ehooks, edata_t *edata, emap_t *emap,
    bool left, bool right) {
	assert(left || right);
	/* Remove the inner boundary which no longer exists. */
	emap_deregister_boundary(tsdn, emap, edata);

	size_t size = edata_size_get(edata);
	size_t size_with_guards = (left && right)
	    ? san_two_side_unguarded_sz(size)
	    : san_one_side_unguarded_sz(size);

	uintptr_t guard1, guard2, addr;
	san_find_unguarded_addr(edata, &guard1, &guard2, &addr, size, left,
	    right);

	assert(edata_state_get(edata) == extent_state_active);
	ehooks_unguard(tsdn, ehooks, (void *)guard1, (void *)guard2);

	/* Update the true addr and usable size of the edata. */
	edata_size_set(edata, size_with_guards);
	edata_addr_set(edata, (void *)addr);
	edata_guarded_set(edata, false);

	/* Then re-register the outer boundary including the guards. */
	emap_register_boundary(tsdn, emap, edata, SC_NSIZES, /* slab */ false);
}

void
tsd_san_init(tsd_t *tsd) {
	*tsd_san_extents_until_guard_smallp_get(tsd) = opt_san_guard_small;
	*tsd_san_extents_until_guard_largep_get(tsd) = opt_san_guard_large;
}
