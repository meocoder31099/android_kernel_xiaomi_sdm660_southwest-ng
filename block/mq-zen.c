/*
*  MQ Zen IO scheduler - adaptation of the legacy zen scheduler
*  for the blk-mq scheduling framework
*
*  Original Zen Copyright (C) 2012 Brandon Berhent <bbedward@gmail.com>
*  Ported to blk-mq for Kernel 4.19
*
*  FCFS, dispatches are back-inserted, deadlines ensure fairness.
*  Should work best with devices where there is no travel delay.
*/

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"

enum zen_data_dir { ASYNC, SYNC };

static const int sync_expire  = HZ / 4;    /* max time before a sync is submitted. */
static const int async_expire = 2 * HZ;    /* ditto for async, these limits are SOFT! */
static const int fifo_batch = 1;

struct zen_data {
	/*
	* run time data
	*/
	struct list_head fifo_list[2];
	struct list_head dispatch;

	unsigned int batching;		/* number of sequential requests made */

	/*
	* tunables
	*/
	int fifo_expire[2];
	int fifo_batch;

	spinlock_t lock;
};

static inline struct zen_data *zen_get_data(struct request_queue *q)
{
	return q->elevator->elevator_data;
}

static void zen_merged_requests(struct request_queue *q, struct request *req,
				struct request *next)
{
	/*
	* if next expires before rq, assign its expire time to req
	* and move into next position (next will be deleted) in fifo
	*/
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {
		if (time_before((unsigned long)next->fifo_time,
				(unsigned long)req->fifo_time)) {
			list_move(&req->queuelist, &next->queuelist);
			req->fifo_time = next->fifo_time;
		}
	}

	/*
	* next request is gone
	*/
	list_del_init(&next->queuelist);
}

/*
* get the first expired request in direction ddir
*/
static struct request *zen_expired_request(struct zen_data *zdata, int ddir)
{
	struct request *rq;

	if (list_empty(&zdata->fifo_list[ddir]))
		return NULL;

	rq = list_first_entry(&zdata->fifo_list[ddir], struct request, queuelist);
	if (time_after_eq(jiffies, (unsigned long)rq->fifo_time))
		return rq;

	return NULL;
}

/*
* zen_check_fifo returns NULL if there are no expired requests on the fifo,
* otherwise it returns the next expired request
*/
static struct request *zen_check_fifo(struct zen_data *zdata)
{
	struct request *rq_sync = zen_expired_request(zdata, SYNC);
	struct request *rq_async = zen_expired_request(zdata, ASYNC);

	if (rq_async && rq_sync) {
		if (time_after((unsigned long)rq_async->fifo_time, 
				(unsigned long)rq_sync->fifo_time))
			return rq_sync;
	} else if (rq_sync) {
		return rq_sync;
	} else if (rq_async) {
		return rq_async;
	}

	return NULL;
}

static struct request *zen_choose_request(struct zen_data *zdata)
{
	/*
	* Retrieve request from available fifo list.
	* Synchronous requests have priority over asynchronous.
	*/
	if (!list_empty(&zdata->fifo_list[SYNC]))
		return list_first_entry(&zdata->fifo_list[SYNC], struct request, queuelist);
	if (!list_empty(&zdata->fifo_list[ASYNC]))
		return list_first_entry(&zdata->fifo_list[ASYNC], struct request, queuelist);

	return NULL;
}

static struct request *__zen_dispatch_request(struct zen_data *zdata)
{
	struct request *rq = NULL;

	/* Priority 1: Handle requeued/at_head requests */
	if (!list_empty(&zdata->dispatch)) {
		rq = list_first_entry(&zdata->dispatch, struct request, queuelist);
		list_del_init(&rq->queuelist);
		goto done;
	}

	/* Priority 2: Check for and issue expired requests to prevent starvation */
	if (zdata->batching > zdata->fifo_batch) {
		zdata->batching = 0;
		rq = zen_check_fifo(zdata);
	}

	/* Priority 3: Regular priority dispatch (SYNC > ASYNC) */
	if (!rq) {
		rq = zen_choose_request(zdata);
		if (!rq)
			return NULL;
	}

	zdata->batching++;
	list_del_init(&rq->queuelist);

done:
	rq->rq_flags |= RQF_STARTED;
	return rq;
}

static struct request *zen_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct zen_data *zdata = hctx->queue->elevator->elevator_data;
	struct request *rq;

	spin_lock(&zdata->lock);
	rq = __zen_dispatch_request(zdata);
	spin_unlock(&zdata->lock);

	return rq;
}

static void zen_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
				bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct zen_data *zdata = q->elevator->elevator_data;
	const int sync = rq_is_sync(rq) ? SYNC : ASYNC;

	if (blk_mq_sched_try_insert_merge(q, rq))
		return;

	blk_mq_sched_request_inserted(rq);

	/* 
	* Passthrough or at_head requests bypass the scheduler lists 
	* and go directly to the dispatch list.
	*/
	if (at_head || blk_rq_is_passthrough(rq)) {
		if (at_head)
			list_add(&rq->queuelist, &zdata->dispatch);
		else
			list_add_tail(&rq->queuelist, &zdata->dispatch);
	} else {
		/* Set expire time and add to respective FIFO list */
		rq->fifo_time = jiffies + zdata->fifo_expire[sync];
		list_add_tail(&rq->queuelist, &zdata->fifo_list[sync]);
	}
}

static void zen_insert_requests(struct blk_mq_hw_ctx *hctx,
				struct list_head *list, bool at_head)
{
	struct request_queue *q = hctx->queue;
	struct zen_data *zdata = q->elevator->elevator_data;

	spin_lock(&zdata->lock);
	while (!list_empty(list)) {
		struct request *rq;

		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);
		zen_insert_request(hctx, rq, at_head);
	}
	spin_unlock(&zdata->lock);
}

static bool zen_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
	struct request_queue *q = hctx->queue;
	struct zen_data *zdata = q->elevator->elevator_data;
	struct request *free = NULL;
	bool ret;

	spin_lock(&zdata->lock);
	ret = blk_mq_sched_try_merge(q, bio, &free);
	spin_unlock(&zdata->lock);

	if (free)
		blk_mq_free_request(free);

	return ret;
}

/* 
* Zen doesn't sort by sector (no rbtrees), so front-merging is not viable.
*/
static int zen_request_merge(struct request_queue *q, struct request **rq,
				struct bio *bio)
{
	return ELEVATOR_NO_MERGE;
}

static bool zen_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct zen_data *zdata = hctx->queue->elevator->elevator_data;

	return !list_empty_careful(&zdata->dispatch) ||
		!list_empty_careful(&zdata->fifo_list[SYNC]) ||
		!list_empty_careful(&zdata->fifo_list[ASYNC]);
}

static int zen_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct zen_data *zdata;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	zdata = kzalloc_node(sizeof(*zdata), GFP_KERNEL, q->node);
	if (!zdata) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}
	eq->elevator_data = zdata;

	INIT_LIST_HEAD(&zdata->fifo_list[SYNC]);
	INIT_LIST_HEAD(&zdata->fifo_list[ASYNC]);
	INIT_LIST_HEAD(&zdata->dispatch);
	zdata->fifo_expire[SYNC] = sync_expire;
	zdata->fifo_expire[ASYNC] = async_expire;
	zdata->fifo_batch = fifo_batch;
	spin_lock_init(&zdata->lock);

	q->elevator = eq;
	return 0;
}

static void zen_exit_queue(struct elevator_queue *e)
{
	struct zen_data *zdata = e->elevator_data;

	BUG_ON(!list_empty(&zdata->fifo_list[SYNC]));
	BUG_ON(!list_empty(&zdata->fifo_list[ASYNC]));

	kfree(zdata);
}

/*
* sysfs parts below
*/
static ssize_t zen_var_show(int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static void zen_var_store(int *var, const char *page)
{
	char *p = (char *) page;
	*var = simple_strtol(p, &p, 10);
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct zen_data *zdata = e->elevator_data;			\
	int __data = __VAR;						\
	if (__CONV)							\
		__data = jiffies_to_msecs(__data);			\
	return zen_var_show(__data, (page));				\
}
SHOW_FUNCTION(zen_sync_expire_show, zdata->fifo_expire[SYNC], 1);
SHOW_FUNCTION(zen_async_expire_show, zdata->fifo_expire[ASYNC], 1);
SHOW_FUNCTION(zen_fifo_batch_show, zdata->fifo_batch, 0);
#undef SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct zen_data *zdata = e->elevator_data;			\
	int __data;							\
	zen_var_store(&__data, (page));					\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	if (__CONV)							\
		*(__PTR) = msecs_to_jiffies(__data);			\
	else								\
		*(__PTR) = __data;					\
	return count;							\
}
STORE_FUNCTION(zen_sync_expire_store, &zdata->fifo_expire[SYNC], 0, INT_MAX, 1);
STORE_FUNCTION(zen_async_expire_store, &zdata->fifo_expire[ASYNC], 0, INT_MAX, 1);
STORE_FUNCTION(zen_fifo_batch_store, &zdata->fifo_batch, 0, INT_MAX, 0);
#undef STORE_FUNCTION

#define ZEN_ATTR(name) \
	__ATTR(name, 0644, zen_##name##_show, zen_##name##_store)

static struct elv_fs_entry zen_attrs[] = {
	ZEN_ATTR(sync_expire),
	ZEN_ATTR(async_expire),
	ZEN_ATTR(fifo_batch),
	__ATTR_NULL
};

static struct elevator_type mq_zen = {
	.ops.mq = {
		.insert_requests	= zen_insert_requests,
		.dispatch_request	= zen_dispatch_request,
		.bio_merge		    = zen_bio_merge,
		.request_merge		= zen_request_merge,
		.requests_merged	= zen_merged_requests,
		.has_work		    = zen_has_work,
		.init_sched		    = zen_init_queue,
		.exit_sched		    = zen_exit_queue,
	},

	.uses_mq	= true,
	.elevator_attrs = zen_attrs,
	.elevator_name = "mq-zen",
	.elevator_alias = "zen",
	.elevator_owner = THIS_MODULE,
};
MODULE_ALIAS("mq-zen-iosched");

static int __init zen_init(void)
{
	return elv_register(&mq_zen);
}

static void __exit zen_exit(void)
{
	elv_unregister(&mq_zen);
}

module_init(zen_init);
module_exit(zen_exit);

MODULE_AUTHOR("Brandon Berhent (Ported by Assistant)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MQ Zen IO scheduler");
MODULE_VERSION("2.0");