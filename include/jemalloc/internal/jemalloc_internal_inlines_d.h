#ifndef JEMALLOC_INTERNAL_INLINES_D_H
#define JEMALLOC_INTERNAL_INLINES_D_H

#include "jemalloc/internal/prof_inlines.h"
#include "jemalloc/internal/arena_externs.h"
#include "jemalloc/internal/emap.h"

#define TCACHE_IND_NONE ((unsigned)-1)
#define TCACHE_IND_AUTOMATIC ((unsigned)-2)
#define ARENA_IND_AUTOMATIC ((unsigned)-1)

JEMALLOC_ALWAYS_INLINE tcache_t *
tcache_get_from_ind(tsd_t *tsd, unsigned tcache_ind, bool slow, bool is_alloc) {
	tcache_t *tcache;
	if (tcache_ind == TCACHE_IND_AUTOMATIC) {
		if (likely(!slow)) {
			/* Getting tcache ptr unconditionally. */
			tcache = tsd_tcachep_get(tsd);
			assert(tcache == tcache_get(tsd));
		} else if (is_alloc ||
		    likely(tsd_reentrancy_level_get(tsd) == 0)) {
			tcache = tcache_get(tsd);
		} else {
			tcache = NULL;
		}
	} else {
		/*
		 * Should not specify tcache on deallocation path when being
		 * reentrant.
		 */
		assert(is_alloc || tsd_reentrancy_level_get(tsd) == 0 ||
		    tsd_state_nocleanup(tsd));
		if (tcache_ind == TCACHE_IND_NONE) {
			tcache = NULL;
		} else {
			tcache = tcaches_get(tsd, tcache_ind);
		}
	}
	return tcache;
}


JEMALLOC_ALWAYS_INLINE bool
maybe_check_alloc_ctx(tsd_t *tsd, void *ptr, emap_alloc_ctx_t *alloc_ctx) {
	if (config_opt_size_checks) {
		emap_alloc_ctx_t dbg_ctx;
		emap_alloc_ctx_lookup(tsd_tsdn(tsd), &arena_emap_global, ptr,
		    &dbg_ctx);
		if (alloc_ctx->szind != dbg_ctx.szind) {
			safety_check_fail_sized_dealloc(
			    /* current_dealloc */ true, ptr,
			    /* true_size */ sz_size2index(dbg_ctx.szind),
			    /* input_size */ sz_size2index(alloc_ctx->szind));
			return true;
		}
		if (alloc_ctx->slab != dbg_ctx.slab) {
			safety_check_fail(
			    "Internal heap corruption detected: "
			    "mismatch in slab bit");
			return true;
		}
	}
	return false;
}

JEMALLOC_ALWAYS_INLINE bool
free_fastpath_nonfast_aligned(void *ptr, bool check_prof) {
	/*
	 * free_fastpath do not handle two uncommon cases: 1) sampled profiled
	 * objects and 2) sampled junk & stash for use-after-free detection.
	 * Both have special alignments which are used to escape the fastpath.
	 *
	 * prof_sample is page-aligned, which covers the UAF check when both
	 * are enabled (the assertion below).  Avoiding redundant checks since
	 * this is on the fastpath -- at most one runtime branch from this.
	 */
	if (config_debug && cache_bin_nonfast_aligned(ptr)) {
		assert(prof_sample_aligned(ptr));
	}

	if (config_prof && check_prof) {
		/* When prof is enabled, the prof_sample alignment is enough. */
		if (prof_sample_aligned(ptr)) {
			return true;
		} else {
			return false;
		}
	}

	if (config_uaf_detection) {
		if (cache_bin_nonfast_aligned(ptr)) {
			return true;
		} else {
			return false;
		}
	}

	return false;
}

/* Returns whether or not the free attempt was successful. */
JEMALLOC_ALWAYS_INLINE bool
ifree_fastpath(void *ptr, size_t size, bool size_hint) {
	tsd_t *tsd = tsd_get(false);
	/* The branch gets optimized away unless tsd_get_allocates(). */
	if (unlikely(tsd == NULL)) {
		return false;
	}
	/*
	 *  The tsd_fast() / initialized checks are folded into the branch
	 *  testing (deallocated_after >= threshold) later in this function.
	 *  The threshold will be set to 0 when !tsd_fast.
	 */
	assert(tsd_fast(tsd) ||
	    *tsd_thread_deallocated_next_event_fastp_get_unsafe(tsd) == 0);

	emap_alloc_ctx_t alloc_ctx;
	if (!size_hint) {
		bool err = emap_alloc_ctx_try_lookup_fast(tsd,
		    &arena_emap_global, ptr, &alloc_ctx);

		/* Note: profiled objects will have alloc_ctx.slab set */
		if (unlikely(err || !alloc_ctx.slab ||
		    free_fastpath_nonfast_aligned(ptr,
		    /* check_prof */ false))) {
			return false;
		}
		assert(alloc_ctx.szind != SC_NSIZES);
	} else {
		/*
		 * Check for both sizes that are too large, and for sampled /
		 * special aligned objects.  The alignment check will also check
		 * for null ptr.
		 */
		if (unlikely(size > SC_LOOKUP_MAXCLASS ||
		    free_fastpath_nonfast_aligned(ptr,
		    /* check_prof */ true))) {
			return false;
		}
		alloc_ctx.szind = sz_size2index_lookup(size);
		/* Max lookup class must be small. */
		assert(alloc_ctx.szind < SC_NBINS);
		/* This is a dead store, except when opt size checking is on. */
		alloc_ctx.slab = true;
	}
	/*
	 * Currently the fastpath only handles small sizes.  The branch on
	 * SC_LOOKUP_MAXCLASS makes sure of it.  This lets us avoid checking
	 * tcache szind upper limit (i.e. tcache_maxclass) as well.
	 */
	assert(alloc_ctx.slab);

	uint64_t deallocated, threshold;
	te_free_fastpath_ctx(tsd, &deallocated, &threshold);

	size_t usize = sz_index2size(alloc_ctx.szind);
	uint64_t deallocated_after = deallocated + usize;
	/*
	 * Check for events and tsd non-nominal (fast_threshold will be set to
	 * 0) in a single branch.  Note that this handles the uninitialized case
	 * as well (TSD init will be triggered on the non-fastpath).  Therefore
	 * anything depends on a functional TSD (e.g. the alloc_ctx sanity check
	 * below) needs to be after this branch.
	 */
	if (unlikely(deallocated_after >= threshold)) {
		return false;
	}
	assert(tsd_fast(tsd));
	bool fail = maybe_check_alloc_ctx(tsd, ptr, &alloc_ctx);
	if (fail) {
		/* See the comment in isfree. */
		return true;
	}

	tcache_t *tcache = tcache_get_from_ind(tsd, TCACHE_IND_AUTOMATIC,
	    /* slow */ false, /* is_alloc */ false);
	cache_bin_t *bin = &tcache->bins[alloc_ctx.szind];

	/*
	 * If junking were enabled, this is where we would do it.  It's not
	 * though, since we ensured above that we're on the fast path.  Assert
	 * that to double-check.
	 */
	assert(!opt_junk_free);

	if (!cache_bin_dalloc_easy(bin, ptr)) {
		return false;
	}

	*tsd_thread_deallocatedp_get(tsd) = deallocated_after;

	return true;
}

JEMALLOC_ALWAYS_INLINE void JEMALLOC_NOTHROW
je_sdallocx_noflags(void *ptr, size_t size) {
	LOG("core.sdallocx.entry", "ptr: %p, size: %zu, flags: 0", ptr,
		size);

	if (!ifree_fastpath(ptr, size, true)) {
		sdallocx_default(ptr, size, 0);
	}

	LOG("core.sdallocx.exit", "");
}

JEMALLOC_ALWAYS_INLINE void JEMALLOC_NOTHROW
je_sdallocx_impl(void *ptr, size_t size, int flags) {
	if (flags != 0 || !ifree_fastpath(ptr, size, true)) {
		sdallocx_default(ptr, size, flags);
	}
}

JEMALLOC_ALWAYS_INLINE void JEMALLOC_NOTHROW
je_free_impl(void *ptr) {
	if (!ifree_fastpath(ptr, 0, false)) {
		free_default(ptr);
	}
}

#endif
