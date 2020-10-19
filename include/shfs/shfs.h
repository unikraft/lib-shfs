/*
 * Simple hash filesystem (SHFS)
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _SHFS_H_
#define _SHFS_H_

#ifndef __KERNEL__
#include <uk/config.h>
#include <stdint.h>
#include <shfs/likely.h>
#include <uk/alloc.h>
#include <uk/allocpool.h>
#include <uk/blkdev.h>
#include <uk/semaphore.h>
#include <uk/assert.h>
#if CONFIG_LIBUKSCHED
#include <uk/wait.h>
#endif /* CONFIG_LIBUKSCHED */
#else
#include <asm-generic/fcntl.h>
#include <target/stubs.h>
#include <target/linux_shfs.h>
#endif

#include "shfs_defs.h"
#ifdef SHFS_STATS
#include "shfs_stats_data.h"
#endif

#ifndef __KERNEL__
#define MAX_NB_TRY_BLKDEVS 64
#else
#define MAX_NB_TRY_BLKDEVS 1
#endif
#define MAX_REQUESTS 1000 /* should be derived from underlying block devices */
#define NB_AIOTOKEN 750 /* should be at least MAX_REQUESTS */

#define LINUX_FIRST_INO_N 10

struct shfs_cache;

struct vol_member {
	struct uk_blkdev *bd;
	uuid_t uuid;
	__sector sfactor;
};

struct vol_info {
	uuid_t uuid;
	char volname[17];
	uint64_t ts_creation;
	uint32_t chunksize;
	chk_t volsize;

	uint8_t nb_members;
	struct vol_member member[SHFS_MAX_NB_MEMBERS];
	uint32_t stripesize;
	uint8_t stripemode;
	uint32_t ioalign;
#if defined CONFIG_SELECT_POLL && defined CAN_POLL_BLKDEV
	int members_maxfd; /* biggest fd number of mounted members (required for select()) */
#endif

	struct htable *bt; /* SHFS bucket entry table */
	void **htable_chunk_cache;
	void *remount_chunk_buffer;
	chk_t htable_ref;
	chk_t htable_bak_ref;
	chk_t htable_len;
	uint32_t htable_nb_buckets;
	uint32_t htable_nb_entries;
	uint32_t htable_nb_entries_per_bucket;
	uint32_t htable_nb_entries_per_chunk;
	uint8_t hlen;

	struct shfs_bentry *def_bentry;

	size_t aiotoken_len;
	struct uk_allocpool *aiotoken_pool; /* token for async I/O */
	struct shfs_cache *chunkcache; /* chunkcache */

#ifdef SHFS_STATS
	struct shfs_mstats mstats;
#endif
};

extern struct vol_info shfs_vol;
extern struct uk_semaphore shfs_mount_lock;
extern int shfs_mounted;
extern unsigned int shfs_nb_open;

int mount_shfs(const unsigned int bd_id[], unsigned int count);
int remount_shfs(void);
int umount_shfs(int force);

#define shfs_blkdevs_count() \
	((shfs_mounted) ? shfs_vol.nb_members : 0)

static inline void shfs_poll_blkdevs(void) {
	register unsigned int i;
	register uint8_t m = shfs_blkdevs_count();

	/*
	 * NOTE: We set up our blkdevs only with 1 queue,
	 *       so we poll just that one
	 */
	for(i = 0; i < m; ++i)
		uk_blkdev_queue_finish_reqs(shfs_vol.member[i].bd, 0);
}

#ifdef CAN_POLL_BLKDEV
#include <sys/select.h>

static inline void shfs_blkdevs_fds(int *fds) {
	register unsigned int i;
	register uint8_t m = shfs_blkdevs_count();

	for(i = 0; i < m; ++i)
		fds[i] = blkdev_get_fd(shfs_vol.member[i].bd);
}

static inline void shfs_blkdevs_fdset(fd_set *fdset) {
	register unsigned int i;
	register uint8_t m = shfs_blkdevs_count();

	for(i = 0; i < m; ++i)
		FD_SET(blkdev_get_fd(shfs_vol.member[i].bd), fdset);
}
#endif /* CAN_POLL_BLKDEV */

/**
 * Fast I/O: asynchronous I/O for volume chunks
 * A request is done via shfs_aio_chunk(). This function returns immediately
 * after the I/O request was set up.
 * Afterwards, the caller has to wait for the I/O completion via
 * tests on shfs_aio_is_done() or by calling shfs_aio_wait() or using a
 * function callback registration on shfs_aio_chunk().
 * The result (return code) of the I/O operation is retrieved via
 * shfs_aio_finalize() (can be called within the user's callback).
 */
struct _shfs_aio_token;
typedef struct _shfs_aio_token SHFS_AIO_TOKEN;
typedef void (shfs_aiocb_t)(SHFS_AIO_TOKEN *t, void *cookie, void *argp);
struct _shfs_aio_token {
	/* token chains (used by shfs_cache) */
	struct _shfs_aio_token *_prev;
	struct _shfs_aio_token *_next;

	unsigned int nb_members;
	unsigned int infly;
	int ret;

	shfs_aiocb_t *cb;
	void *cb_cookie;
	void *cb_argp;

	struct uk_blkreq req[];
};

/*
 * Setups a asynchronous I/O operation and returns a token
 * NULL is returned if the async I/O operation could not be set up
 * The callback registration is optional and can be seen as an alternative way
 * to wait for the I/O completation compared to using shfs_aio_is_done()
 * or shfs_aio_wait()
 * cb_cookie and cb_argp are user definable values that get passed
 * to the user defined callback.
 */
SHFS_AIO_TOKEN *shfs_aio_chunk(chk_t start, chk_t len, int write, void *buffer,
                               shfs_aiocb_t *cb, void *cb_cookie, void *cb_argp);
#define shfs_aread_chunk(start, len, buffer, cb, cb_cookie, cb_argp)	  \
	shfs_aio_chunk((start), (len), 0, (buffer), (cb), (cb_cookie), (cb_argp))
#define shfs_awrite_chunk(start, len, buffer, cb, cb_cookie, cb_argp) \
	shfs_aio_chunk((start), (len), 1, (buffer), (cb), (cb_cookie), (cb_argp))

/* TODO: Currently unsupported by ukblkdev */
static inline void shfs_aio_wait_slot(void) {
/*
	register unsigned int i;
	register uint8_t m = shfs_blkdevs_count();

	for(i = 0; i < m; ++i)
		blkdev_async_io_wait_slot(shfs_vol.member[i].bd);
*/
#if CONFIG_LIBUKSCHED
	uk_sched_yield();
#endif
}

/*
 * Internal AIO token management (do not use this functions directly!)
 */
#ifndef __KERNEL__
SHFS_AIO_TOKEN *shfs_aio_pick_token(void);

#define shfs_aio_put_token(t) \
	uk_allocpool_return(shfs_vol.aiotoken_pool, t)

static inline void shfs_aio_setup_token_mio(SHFS_AIO_TOKEN *t,
					    unsigned int member,
					    __sector start, __sector len,
					    void *buf)
{
	UK_ASSERT(t);
	UK_ASSERT(member < t->nb_members);

	t->req[member].start_sector = start;
	t->req[member].nb_sectors = len;
	t->req[member].aio_buf = buf;
}
#else
static inline SHFS_AIO_TOKEN *shfs_aio_pick_token(void)
{
	return kmalloc(sizeof(SHFS_AIO_TOKEN), GFP_KERNEL);
}
#define shfs_aio_put_token(t) kfree(t)
#endif

/*
 * Returns 1 if the I/O operation has finished, 0 otherwise
 */
#define shfs_aio_is_done(t)	  \
	(!(t) || (t)->infly == 0)

/*
 * Busy-waiting until the async I/O operation is completed
 *
 * Note: This function will end up in a deadlock when there is no
 * SHFS volume mounted
 */
#ifndef __KERNEL__
#define shfs_aio_wait_nosched(t) \
	while (!shfs_aio_is_done((t))) { \
		shfs_poll_blkdevs(); \
	}

#if CONFIG_LIBUKSCHED
#define shfs_aio_wait(t)		 \
	while (!shfs_aio_is_done((t))) { \
		shfs_poll_blkdevs(); \
		if (!shfs_aio_is_done((t)))	\
			uk_sched_yield();	\
	}
#else
#define shfs_aio_wait(t) shfs_aio_wait_nosched(t)
#endif /* CONFIG_LIBUKSCHED */
#else
/* Plan is to use shfs_aio_chunk only to read initial metadata. So it
 * is not critical to do only synchronous reads
 */
#define shfs_aio_wait_nosched(t) do { \
	t->infly = 0; \
	t->ret = 0; \
} while (0)
#define shfs_aio_wait(t) shfs_aio_wait_nosched(t)
#endif

/*
 * Destroys an asynchronous I/O token after the I/O completed
 * This function returns the return code of the IO operation
 *
 * Note: This function has and can only be called after an I/O is done!
 */
static inline int shfs_aio_finalize(SHFS_AIO_TOKEN *t)
{
	int ret;

	UK_ASSERT(!t->infly);
	ret = t->ret;
	shfs_aio_put_token(t);

	return ret;
}

/**
 * Slow I/O: sequential sync I/O for volume chunks
 * These functions are intended to be used during mount/umount time
 */
static inline int shfs_io_chunk(chk_t start, chk_t len, int write, void *buffer) {
	SHFS_AIO_TOKEN *t;

 retry:
	t = shfs_aio_chunk(start, len, write, buffer, NULL, NULL, NULL);
	if (unlikely(!t && errno == EBUSY)) {
		shfs_poll_blkdevs();
		shfs_aio_wait_slot(); /* yield CPU */
		goto retry;
	}
	if (unlikely(!t))
		return -errno;

	shfs_aio_wait(t);
	return shfs_aio_finalize(t);
}
#define shfs_read_chunk(start, len, buffer) \
	shfs_io_chunk((start), (len), 0, (buffer))
#define shfs_write_chunk(start, len, buffer) \
	shfs_io_chunk((start), (len), 1, (buffer))

static inline int shfs_io_chunk_nosched(chk_t start, chk_t len, int write, void *buffer) {
	SHFS_AIO_TOKEN *t;

 retry:
	t = shfs_aio_chunk(start, len, write, buffer, NULL, NULL, NULL);
	if (unlikely(!t && errno == EBUSY))
		goto retry;
	if (unlikely(!t))
		return -errno;

	shfs_aio_wait_nosched(t);
	return shfs_aio_finalize(t);
}
#define shfs_read_chunk_nosched(start, len, buffer) \
	shfs_io_chunk_nosched((start), (len), 0, (buffer))
#define shfs_write_chunk_nosched(start, len, buffer) \
	shfs_io_chunk_nosched((start), (len), 1, (buffer))
#endif /* _SHFS_H_ */
