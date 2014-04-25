/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 *
 * Copyright (C) 2008 MacZFS
 * Copyright (C) 2013 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <spl-debug.h>
#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/list.h>
#include "spl-bmalloc.h"

uint64_t physmem = 0;
static uint64_t total_in_use = 0;

extern int vm_pool_low(void);

extern unsigned int vm_page_free_count;
extern unsigned int vm_page_speculative_count;

void spl_register_oids(void);
void spl_unregister_oids(void);

SYSCTL_DECL(_spl);
SYSCTL_NODE( , OID_AUTO, spl, CTLFLAG_RW, 0, "Solaris Porting Layer");
struct sysctl_oid_list sysctl__spl_children;

SYSCTL_QUAD(_spl, OID_AUTO, kmem_bytes_total, CTLFLAG_RD,
            &total_in_use, "kmem.total bytes allocated");

extern uint32_t zfs_threads;
SYSCTL_INT(_spl, OID_AUTO, num_threads,
           CTLFLAG_RD, &zfs_threads, 0,
           "Num threads");

// Lock manager stuff
static lck_grp_t        *kmem_lock_group = NULL;
static lck_attr_t       *kmem_lock_attr = NULL;
static lck_grp_attr_t   *kmem_group_attr = NULL;

void *
zfs_kmem_alloc(size_t size, int kmflags)
{
    return bmalloc(size);
}

void *
zfs_kmem_zalloc(size_t size, int kmflags)
{
    void *p = bmalloc(size);
    
    if (p) {
        bzero(p, size);
        //atomic_add_64(&total_in_use, size);
    }
    
    return (p);
}

void
zfs_kmem_free(void *buf, size_t size)
{
    bfree(buf, size);
    //atomic_sub_64(&total_in_use, size);
}

void
spl_kmem_init(uint64_t total_memory)
{
    printf("SPL: Total memory %llu\n", total_memory);
    spl_register_oids();
    
    // Initialise spinlocks
    kmem_lock_attr = lck_attr_alloc_init();
    kmem_group_attr = lck_grp_attr_alloc_init();
    kmem_lock_group  = lck_grp_alloc_init("kmem-spinlocks", kmem_group_attr);
}

void
spl_kmem_fini(void)
{
    spl_unregister_oids();
}

uint64_t
kmem_size(void)
{
	return (physmem * PAGE_SIZE);
}

uint64_t
kmem_used(void)
{
    return total_in_use;
}

uint64_t
kmem_avail(void)
{
    return (vm_page_free_count + vm_page_speculative_count) * PAGE_SIZE;
}

int spl_vm_pool_low(void)
{
    static int tick_counter = 0;
    
    int r = vm_pool_low();
    
    if(r) {
        bmalloc_release_memory();
    }
    
    // FIXME - this should be in its own thread
    // that calls garbage collect at least every
    // 5 seconds.
    tick_counter++;
    if(tick_counter % 5 == 0) {
        tick_counter = 0;
        bmalloc_garbage_collect();
    }
    
    return r;
}

static int
kmem_std_constructor(void *mem, int size __unused, void *private, int flags)
{
	struct kmem_cache *cache = private;
    
	return (cache->kc_constructor(mem, cache->kc_private, flags));
}

static void
kmem_std_destructor(void *mem, int size __unused, void *private)
{
	struct kmem_cache *cache = private;
    
	cache->kc_destructor(mem, cache->kc_private);
}

typedef struct cache_entry {
    void* object;
    list_node_t cache_entry_link_node;
} cache_entry_t;

typedef struct cache_impl {
    list_t      entries;
    list_t      free_list;
    lck_spin_t* lock;
} cache_impl_t;

kmem_cache_t *
kmem_cache_create(char *name, size_t bufsize, size_t align,
                  int (*constructor)(void *, void *, int), void (*destructor)(void *, void *),
                  void (*reclaim)(void *), void *private, vmem_t *vmp, int cflags)
{
	kmem_cache_t *cache;
    
	ASSERT(vmp == NULL);
    
	cache = zfs_kmem_alloc(sizeof(*cache), KM_SLEEP);
    cache->impl = zfs_kmem_alloc(sizeof(cache_impl_t), KM_SLEEP);
    cache->impl->lock = lck_spin_alloc_init(kmem_lock_group, kmem_lock_attr);
    list_create(&cache->impl->entries, sizeof(cache_entry_t), offsetof(cache_entry_t, cache_entry_link_node));
    list_create(&cache->impl->free_list, sizeof(cache_entry_t), offsetof(cache_entry_t, cache_entry_link_node));
    
	strlcpy(cache->kc_name, name, sizeof(cache->kc_name));
	cache->kc_constructor = constructor;
	cache->kc_destructor = destructor;
	cache->kc_reclaim = reclaim;
	cache->kc_private = private;
	cache->kc_size = bufsize;
    
	return (cache);
}

void
kmem_cache_destroy(kmem_cache_t *cache)
{
    // clear any remaining cache entries
    while (!list_is_empty(&cache->impl->entries)) {
        cache_entry_t* entry = list_head(&cache->impl->entries);
        list_remove_head(&cache->impl->entries);
        
        // FIXME determine if we have to destruct these objects
        zfs_kmem_free(entry->object, cache->kc_size);
        zfs_kmem_free(entry, sizeof(cache_entry_t));
    }
    
    // Destroy cache data structures.
    while (!list_is_empty(&cache->impl->free_list)) {
        cache_entry_t* entry = list_head(&cache->impl->free_list);
        list_remove_head(&cache->impl->free_list);
        zfs_kmem_free(entry, sizeof(cache_entry_t));
    }
    
    lck_spin_destroy(cache->impl->lock, kmem_lock_group);
    zfs_kmem_free(cache->impl, sizeof(cache_impl_t));
	zfs_kmem_free(cache, sizeof(*cache));
}

void *
kmem_cache_alloc(kmem_cache_t *cache, int flags)
{
	void *p = 0;
    
    lck_spin_lock(cache->impl->lock);
    if (list_is_empty(&cache->impl->entries)) {
        // Object not available in cache, create a new instance
        lck_spin_unlock(cache->impl->lock);
        
        if (flags & KM_ZERO) {
            p = zfs_kmem_zalloc(cache->kc_size, flags);
        } else {
            p = zfs_kmem_alloc(cache->kc_size, flags);
        }
        
        if (p  && cache->kc_constructor) {
            kmem_std_constructor(p, cache->kc_size, cache, flags);
        }
    } else {
        // Object is available in the cache
        cache_entry_t* entry = list_head(&cache->impl->entries);
        list_remove_head(&cache->impl->entries);
        p = entry->object;
        list_insert_head(&cache->impl->free_list, entry);
        lck_spin_unlock(cache->impl->lock);
    }
    
	return (p);
}

void
kmem_cache_free(kmem_cache_t *cache, void *buf)
{
    cache_entry_t* entry = 0;
    
    lck_spin_lock(cache->impl->lock);
    
    if (list_is_empty(&cache->impl->free_list)) {
        entry = zfs_kmem_alloc(sizeof(cache_entry_t), KM_NOSLEEP);
    } else {
        entry = list_head(&cache->impl->free_list);
        list_remove_head(&cache->impl->free_list);
    }
    
    lck_spin_unlock(cache->impl->lock);
    
    if(entry) {
        entry->object = buf;
        list_link_init(&entry->cache_entry_link_node);
        
        lck_spin_lock(cache->impl->lock);
        list_insert_head(&cache->impl->entries, entry);
        lck_spin_unlock(cache->impl->lock);
        
    } else {
        if (cache->kc_destructor) {
            kmem_std_destructor(buf, cache->kc_size, cache);
        }
        zfs_kmem_free(buf, cache->kc_size);
    }
}


/*
 * Call the registered reclaim function for a cache.  Depending on how
 * many and which objects are released it may simply repopulate the
 * local magazine which will then need to age-out.  Objects which cannot
 * fit in the magazine we will be released back to their slabs which will
 * also need to age out before being release.  This is all just best
 * effort and we do not want to thrash creating and destroying slabs.
 */
void
kmem_cache_reap_now(kmem_cache_t *skc)
{
}

int
kmem_debugging(void)
{
	return (0);
}

void *
calloc(size_t n, size_t s)
{
	return (kmem_zalloc(n * s, KM_NOSLEEP));
}

void
strfree(char *str)
{
    bfree(str, strlen(str) + 1);
}

char *kvasprintf(const char *fmt, va_list ap)
{
    unsigned int len;
    char *p;
    va_list aq;
    
    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);
    
    p = bmalloc(len+1);
    if (!p)
        return NULL;
    
    vsnprintf(p, len+1, fmt, ap);
    
    return p;
}

char *
kmem_vasprintf(const char *fmt, va_list ap)
{
    va_list aq;
    char *ptr;
    
    do {
        va_copy(aq, ap);
        ptr = kvasprintf(fmt, aq);
        va_end(aq);
    } while (ptr == NULL);
    
    return ptr;
}

char *
kmem_asprintf(const char *fmt, ...)
{
    va_list ap;
    char *ptr;
    
    do {
        va_start(ap, fmt);
        ptr = kvasprintf(fmt, ap);
        va_end(ap);
    } while (ptr == NULL);
    
    return ptr;
}

void spl_register_oids(void)
{
    sysctl_register_oid(&sysctl__spl);
    sysctl_register_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_register_oid(&sysctl__spl_num_threads);
}

void spl_unregister_oids(void)
{
    sysctl_unregister_oid(&sysctl__spl);
    sysctl_unregister_oid(&sysctl__spl_kmem_bytes_total);
    sysctl_unregister_oid(&sysctl__spl_num_threads);
}
