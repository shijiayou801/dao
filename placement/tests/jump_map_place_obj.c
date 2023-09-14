/**
 * (C) Copyright 2016-2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */
#define D_LOGFAC	DD_FAC(tests)

#include <daos/common.h>
#include <daos/placement.h>
#include <daos.h>
#include <daos/object.h>
#include "place_obj_common.h"
/* Gain some internal knowledge of pool server */
#include "../../pool/rpc.h"
#include "../../pool/srv_pool_map.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <daos/tests_lib.h>
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static bool g_verbose;

#define skip_msg(msg) do { print_message(__FILE__":" STR(__LINE__) \
			" Skipping > "msg"\n"); skip(); } \
			while (0)
#define is_true assert_true
#define is_false assert_false

void verbose_msg(char *msg, ...)
{
	if (g_verbose) {
		va_list vargs;

		va_start(vargs, msg);
		vprint_message(msg, vargs);
		va_end(vargs);
	}
}

static void
gen_maps(int num_domains, int nodes_per_domain, int vos_per_target,
	 struct pool_map **po_map, struct pl_map **pl_map)
{
	gen_pool_and_placement_map(num_domains, nodes_per_domain,
				   vos_per_target, PL_TYPE_JUMP_MAP,
				   po_map, pl_map);
	assert_non_null(*po_map);
	assert_non_null(*pl_map);
}

static void
gen_oid(daos_obj_id_t *oid, uint64_t lo, uint64_t hi, daos_oclass_id_t cid)
{
	int rc;

	oid->lo = lo;
	/* make sure top 32 bits are unset (DAOS only) */
	oid->hi = hi & 0xFFFFFFFF;
	rc = daos_obj_set_oid_by_class(oid, 0, cid, 0);
	assert_rc_equal(rc, cid == OC_UNKNOWN ? -DER_INVAL : 0);
}

#define assert_placement_success(pl_map, cid) \
	do {\
		daos_obj_id_t __oid; \
		struct pl_obj_layout *__layout = NULL; \
		gen_oid(&__oid, 1, UINT64_MAX, cid); \
		assert_success(plt_obj_place(__oid, &__layout, pl_map, \
				false)); \
		pl_obj_layout_free(__layout); \
	} while (0)

#define assert_invalid_param(pl_map, cid)		\
	do {						\
		daos_obj_id_t __oid;			\
		struct pl_obj_layout *__layout = NULL;	\
		int rc;					\
		gen_oid(&__oid, 1, UINT64_MAX, cid);	\
		rc = plt_obj_place(__oid, &__layout,	\
				   pl_map, false);	\
		assert_rc_equal(rc, -DER_INVAL);	\
	} while (0)

static void
my_test(void **state)
{
	struct pool_map		*po_map;
	struct pl_map		*pl_map;

	gen_maps(1, 1, 2, &po_map, &pl_map);
	assert_invalid_param(pl_map, OC_RP_2G1);
}



/* Results provided by the pl_obj_find_rebuild/addition/reint functions */
struct remap_result {
	uint32_t		*tgt_ranks;
	uint32_t		*ids; /* shard ids */
	uint32_t		 nr;
	uint32_t		 out_nr;
	/* Should skip this 'find' operation. This is
	 * a workaround for DAOS-6516
	 */
	bool			 skip;
};

static void
rr_init(struct remap_result *rr, uint32_t nr)
{
	D_ALLOC_ARRAY(rr->ids, nr);
	D_ALLOC_ARRAY(rr->tgt_ranks, nr);
	rr->nr = nr;
	rr->out_nr = 0;
}

static void
rr_fini(struct remap_result *rr)
{
	D_FREE(rr->ids);
	D_FREE(rr->tgt_ranks);
	memset(rr, 0, sizeof(*rr));
}

static void
rr_reset(struct remap_result *rr)
{
	memset(rr->ids, 0, rr->nr * sizeof(*rr->ids));
	memset(rr->tgt_ranks, 0, rr->nr * sizeof(*rr->tgt_ranks));
	rr->out_nr = 0;
}


static void
rr_print(struct remap_result *map)
{
	int i;

	if (map->skip) {
		print_message("\t Skipped\n");
		return;
	}
	for (i = 0; i < map->out_nr; i++)
		print_message("\tshard %d -> target %d\n",
			      map->ids[i], map->tgt_ranks[i]);
	if (i == 0)
		print_message("\t(Nothing)\n");
}

typedef int (*find_fn)(struct pl_map *map, struct daos_obj_md *md,
		       struct daos_obj_shard_md *shard_md,
		       uint32_t reint_ver, uint32_t *tgt_rank,
		       uint32_t *shard_id, unsigned int array_size);

static void
rr_find(struct pl_map *pl_map, struct daos_obj_md *md, uint32_t ver,
	struct remap_result *rr, find_fn fn)
{
	if (rr->skip)
		rr_reset(rr);
	else
		rr->out_nr = fn(pl_map, md, NULL, ver, rr->tgt_ranks,
				rr->ids, rr->nr);
}

/* Testing context */
struct jm_test_ctx {
	struct pool_map		*po_map;
	struct pl_map		*pl_map;
	struct pl_obj_layout	*layout;
	uuid_t			 pl_uuid;
	/* remember shard's original targets */
	uint32_t		*shard_targets;


	/* results from scanning (find_rebuild/reint/addition) */
	struct remap_result	rebuild;
	struct remap_result	reint;
	struct remap_result	new;


	uint32_t		 ver; /* Maintain version of pool map */

	daos_obj_id_t		 oid; /* current oid used for testing */

	/* configuration of the system. Number of domains(racks), nodes
	 * per domain, and targets per node
	 * target_nr is used for standard config, domain_target_nr used for
	 * non standard configs
	 */
	bool			 is_standard_config;
	uint32_t		 domain_nr;
	uint32_t		 node_nr;
	uint32_t		 target_nr;
	uint32_t		 *domain_target_nr;

	daos_oclass_id_t	 object_class;
	bool			 are_maps_generated;
	bool			 is_layout_set;
	bool			 enable_print_layout;
	bool			 enable_print_debug_msgs;
	bool			 enable_print_pool;
};

/* shard: struct pl_obj_shard * */
#define jtc_for_each_layout_shard(ctx, shard, i) \
	for (i = 0, shard = jtc_get_layout_shard(ctx, 0); \
		i < jtc_get_layout_nr(ctx); \
		i++, shard = jtc_get_layout_shard(ctx, i))

static void
__jtc_maps_free(struct jm_test_ctx *ctx)
{
	if (ctx->are_maps_generated) {
		free_pool_and_placement_map(ctx->po_map, ctx->pl_map);
		ctx->po_map = NULL;
		ctx->pl_map = NULL;
	}
}

static void
__jtc_layout_free(struct jm_test_ctx *ctx)
{
	if (ctx->is_layout_set) {
		pl_obj_layout_free(ctx->layout);
		ctx->layout = NULL;
	}
}

static void
jtc_print_pool(struct jm_test_ctx *ctx)
{
	pool_map_print(ctx->po_map);
}

static void
jtc_print_layout_force(struct jm_test_ctx *ctx)
{
	print_layout(ctx->layout);
}

static void
jtc_maps_gen(struct jm_test_ctx *ctx)
{
	/* Allocates the maps. must be freed with jtc_maps_free if already
	 * allocated
	 */
	__jtc_maps_free(ctx);

	gen_pool_and_placement_map(ctx->domain_nr, ctx->node_nr,
				   ctx->target_nr, PL_TYPE_JUMP_MAP,
				   &ctx->po_map, &ctx->pl_map);

	assert_non_null(ctx->po_map);
	assert_non_null(ctx->pl_map);
	ctx->are_maps_generated = true;
}


static int
jtc_pool_map_extend(struct jm_test_ctx *ctx, uint32_t domain_count,
		    uint32_t node_count, uint32_t target_count)
{
	struct pool_buf	*map_buf;
	uint32_t	map_version;
	int		ntargets;
	int		rc, i;
	d_rank_list_t	rank_list;
	uint32_t	domains[] = {255, 0, 5, /* root */
				     1, 101, 1,
				     1, 102, 1,
				     1, 103, 1,
				     1, 104, 1,
				     1, 105, 1};
	const size_t	tuple_size = 3;
	const size_t	max_domains = 5;
	uint32_t	domain_tree_len;
	uint32_t	domains_only_len;
	uint32_t	ranks_per_domain;
	uint32_t	*domain_tree;
	uuid_t		target_uuids[] = {"12345678", "23456789",
					  "34567890", "4567890a" };

	/* Only support add same node/target domain for the moment */
	assert_int_equal(ctx->target_nr, target_count);
	assert_int_equal(ctx->node_nr, node_count);
	if (domain_count > max_domains)
		fail_msg("Only %lu domains can be added", max_domains);

	/* Build the fault domain tree */
	ranks_per_domain = node_count / domain_count;
	/* Update domains array to be consistent with input params */
	domains[tuple_size - 1] = domain_count; /* root */
	for (i = 0; i < domain_count; i++) {
		uint32_t start_idx = (i + 1) * tuple_size;

		domains[start_idx + tuple_size - 1] = ranks_per_domain;
	}

	domains_only_len = (domain_count + 1) * tuple_size;
	domain_tree_len = domains_only_len + node_count;
	D_ALLOC_ARRAY(domain_tree, domain_tree_len);
	assert_non_null(domain_tree);

	memcpy(domain_tree, domains,
	       sizeof(uint32_t) * domains_only_len);

	for (i = 0; i < node_count; i++) {
		uint32_t idx = domains_only_len + i;

		domain_tree[idx] = i;
	}

	rank_list.rl_nr = node_count;
	D_ALLOC_ARRAY(rank_list.rl_ranks, node_count);
	assert_non_null(rank_list.rl_ranks);
	for (i = 0; i < node_count; i++)
		rank_list.rl_ranks[i] = ctx->domain_nr + i;

	ntargets = node_count * target_count;
	if (ntargets > ARRAY_SIZE(target_uuids))
		fail_msg("Only %lu targets can be added",
			 ARRAY_SIZE(target_uuids));

	map_version = pool_map_get_version(ctx->po_map) + 1;

	rc = gen_pool_buf(ctx->po_map, &map_buf, map_version, domain_tree_len, node_count,
			  ntargets, domain_tree, &rank_list, target_count);
	D_FREE(domain_tree);
	assert_success(rc);

	/* Extend the current pool map */
	rc = pool_map_extend(ctx->po_map, map_version, map_buf);
	D_FREE(map_buf);
	assert_success(rc);

	ctx->domain_nr += domain_count;

	jtc_print_pool(ctx);

	D_FREE(rank_list.rl_ranks);

	return rc;
}

static void
jtc_scan(struct jm_test_ctx *ctx)
{
	struct daos_obj_md md = {.omd_id = ctx->oid, .omd_ver = ctx->ver};

	//rr_find(ctx->pl_map, &md, ctx->ver, &ctx->reint, pl_obj_find_reint);
	
	fprintf(stderr, "\nfind addition\n");
	rr_find(ctx->pl_map, &md, ctx->ver, &ctx->new, pl_obj_find_addition);
	
	fprintf(stderr, "\nfind rebuild\n");
	rr_find(ctx->pl_map, &md, ctx->ver, &ctx->rebuild, pl_obj_find_rebuild);

	fprintf(stderr, "\nfind drain\n");
	rr_find(ctx->pl_map, &md, ctx->ver, &ctx->rebuild, pl_obj_find_drain);

	if (ctx->enable_print_layout) {
		print_message("-- Rebuild Scan --\n");
		rr_print(&ctx->rebuild);

		print_message("-- Reint Scan --\n");
		rr_print(&ctx->reint);

		print_message("-- New Scan --\n");
		rr_print(&ctx->new);
	}

	fprintf(stderr, "end of scan \n\n");
}

static int
jtc_create_layout(struct jm_test_ctx *ctx)
{
	int rc;

	D_ASSERT(ctx != NULL);
	D_ASSERT(ctx->pl_map != NULL);

	/* place object will allocate the layout so need to free first
	 * if already allocated
	 */
	__jtc_layout_free(ctx);
	rc = plt_obj_place(ctx->oid, &ctx->layout, ctx->pl_map,
			   ctx->enable_print_layout);

	if (rc == 0)
		ctx->is_layout_set = true;
	return rc;
}

static int
jtc_layout_shard_tgt(struct jm_test_ctx *ctx, uint32_t shard_idx)
{
	return  ctx->layout->ol_shards[shard_idx].po_target;
}

static void
jtc_set_status_on_target(struct jm_test_ctx *ctx, const int status,
			 const uint32_t id)
{
	struct pool_target_id_list tgts;
	struct pool_target_id tgt_id = {.pti_id = id};

	tgts.pti_ids = &tgt_id;
	tgts.pti_number = 1;

	int rc = ds_pool_map_tgts_update(ctx->po_map, &tgts, status,
					 false, &ctx->ver,
					 ctx->enable_print_debug_msgs);
	/* Make sure pool map changed */
	assert_true(ctx->ver > 0);
	assert_success(rc);

	pool_map_update_failed_cnt(ctx->po_map);
	rc = pool_map_set_version(ctx->po_map, ctx->ver);
	assert_success(rc);

	pl_map_update(ctx->pl_uuid, ctx->po_map, false, PL_TYPE_JUMP_MAP);
	jtc_print_pool(ctx);
}

static void
jtc_set_status_on_shard_target(struct jm_test_ctx *ctx, const int status,
			       const uint32_t shard_idx)
{
	int id = jtc_layout_shard_tgt(ctx, shard_idx);

	D_ASSERT(id >= 0);
	jtc_set_status_on_target(ctx, status, id);
}

static void
jtc_set_status_on_all_shards(struct jm_test_ctx *ctx, const int status)
{
	int i;

	for (i = 0; i < ctx->layout->ol_nr; i++)
		jtc_set_status_on_shard_target(ctx, status, i);
	jtc_print_pool(ctx);
}

static void
jtc_set_status_on_first_shard(struct jm_test_ctx *ctx, const int status)
{
	jtc_set_status_on_target(ctx, status, jtc_layout_shard_tgt(ctx, 0));
}

static void
jtc_set_object_meta(struct jm_test_ctx *ctx,
		    daos_oclass_id_t object_class, uint64_t lo, uint64_t hi)
{
	ctx->object_class = object_class;
	gen_oid(&ctx->oid, lo, hi, object_class);
}

static struct pl_obj_shard *
jtc_get_layout_shard(struct jm_test_ctx *ctx, const int shard_idx)
{
	if (shard_idx < ctx->layout->ol_nr)
		return &ctx->layout->ol_shards[shard_idx];

	return NULL;
}

static uint32_t
jtc_get_layout_nr(struct jm_test_ctx *ctx)
{
	return ctx->layout->ol_nr;
}

/* return the number of targets with -1 as target/shard */
static int
jtc_get_layout_bad_count(struct jm_test_ctx *ctx)
{
	struct pl_obj_shard	*shard;
	int			 i;
	int			 result = 0;

	jtc_for_each_layout_shard(ctx, shard, i)
		if (shard->po_shard == -1 || shard->po_target == -1)
			result++;

	return result;

}

static int
jtc_get_layout_rebuild_count(struct jm_test_ctx *ctx)
{
	uint32_t result = 0;
	uint32_t i;
	struct pl_obj_shard *shard;

	jtc_for_each_layout_shard(ctx, shard, i) {
		if (shard->po_rebuilding)
			result++;
	}

	return result;
}

static bool
jtc_layout_has_duplicate(struct jm_test_ctx *ctx)
{
	int i;
	int target_num;
	bool *target_set;
	bool result = false;

	D_ASSERT(ctx != NULL);
	D_ASSERT(ctx->po_map != NULL);
	const uint32_t total_targets = pool_map_target_nr(ctx->po_map);

	D_ALLOC_ARRAY(target_set, total_targets);
	D_ASSERT(target_set != NULL);

	for (i = 0; i < ctx->layout->ol_nr; i++) {
		target_num = ctx->layout->ol_shards[i].po_target;

		if (target_num != -1) {
			if (target_set[target_num]) { /* already saw */
				print_message("Found duplicate target: %d\n",
					      target_num);
				result = true;
			}
			target_set[target_num] = true;
		}
	}
	D_FREE(target_set);

	return result;
}

static void
jtc_enable_debug(struct jm_test_ctx *ctx)
{
	ctx->enable_print_layout = true;
	ctx->enable_print_debug_msgs = true;
}

static void
jtc_set_standard_config(struct jm_test_ctx *ctx, uint32_t domain_nr,
			uint32_t node_nr, uint32_t target_nr)
{
	ctx->is_standard_config = true;
	ctx->domain_nr = domain_nr;
	ctx->node_nr = node_nr;
	ctx->target_nr = target_nr;
	jtc_maps_gen(ctx);
}

static void
__jtc_init(struct jm_test_ctx *ctx, daos_oclass_id_t object_class,
	   bool enable_debug)
{
	memset(ctx, 0, sizeof(*ctx));

	if (enable_debug)
		jtc_enable_debug(ctx);

	ctx->ver = 1; /* Should start with pool map version 1 */
	uuid_generate(ctx->pl_uuid);

	jtc_set_object_meta(ctx, object_class, 1, UINT64_MAX);

	/* hopefully 10x domain is enough */
	rr_init(&ctx->rebuild, 32);
	rr_init(&ctx->reint, 32);
	rr_init(&ctx->new, 32);
}

static void
jtc_init(struct jm_test_ctx *ctx, uint32_t domain_nr, uint32_t node_nr,
	 uint32_t target_nr, daos_oclass_id_t object_class, bool enable_debug)
{
	__jtc_init(ctx, object_class, enable_debug);

	jtc_set_standard_config(ctx, domain_nr, node_nr, target_nr);
}

static void
jtc_init_non_standard(struct jm_test_ctx *ctx, uint32_t domain_nr,
		      uint32_t target_nr[], daos_oclass_id_t object_class,
		      bool enable_debug)
{
	__jtc_init(ctx, object_class, enable_debug);

	ctx->is_standard_config = false;
	ctx->domain_nr = domain_nr;
	ctx->node_nr = 1;
	ctx->domain_target_nr = target_nr;

	gen_pool_and_placement_map_non_standard(domain_nr, (int *)target_nr,
						PL_TYPE_JUMP_MAP,
						&ctx->po_map,
						&ctx->pl_map);
	ctx->are_maps_generated = true;
}

static void
jtc_init_with_layout(struct jm_test_ctx *ctx, uint32_t domain_nr,
		     uint32_t node_nr, uint32_t target_nr,
		     daos_oclass_id_t object_class, bool enable_debug)
{
	jtc_init(ctx, domain_nr, node_nr, target_nr, object_class,
		 enable_debug);
	assert_success(jtc_create_layout(ctx));
}

static void
jtc_fini(struct jm_test_ctx *ctx)
{
	__jtc_layout_free(ctx);
	__jtc_maps_free(ctx);

	rr_fini(&ctx->rebuild);
	rr_fini(&ctx->reint);
	rr_fini(&ctx->new);

	if (ctx->shard_targets)
		D_FREE(ctx->shard_targets);

	memset(ctx, 0, sizeof(*ctx));
}

#define JTC_CREATE_AND_ASSERT_HEALTHY_LAYOUT(ctx) \
	__jtc_create_and_assert_healthy_layout(__FILE__, __LINE__, ctx)

#define assert_int_equal_s(a, b, file, line) \
	do {\
	uint64_t __a = a; \
	uint64_t __b = b; \
	if (__a != __b) \
		fail_msg("%s:%d"DF_U64" != "DF_U64"\n", file, line, __a, __b); \
	} while (0)

static void
__jtc_create_and_assert_healthy_layout(char *file, int line,
				       struct jm_test_ctx *ctx)
{
	int rc = jtc_create_layout(ctx);

	if (rc != 0)
		fail_msg("%s:%d Layout create failed: "DF_RC"\n",
			 file, line, DP_RC(rc));
	jtc_scan(ctx);

	assert_int_equal_s(0, jtc_get_layout_rebuild_count(ctx),
			   file, line);
	assert_int_equal_s(0, jtc_get_layout_bad_count(ctx),
			   file, line);
	assert_int_equal_s(false, jtc_layout_has_duplicate(ctx), file, line);
	assert_int_equal_s(0, ctx->rebuild.out_nr, file, line);
	assert_int_equal_s(0, ctx->reint.out_nr, file, line);
	assert_int_equal_s(0, ctx->new.out_nr, file, line);
}

static int
jtc_get_layout_target_count(struct jm_test_ctx *ctx)
{
	if (ctx->layout != NULL)
		return ctx->layout->ol_nr;
	return 0;
}

static bool
jtc_has_shard_with_target_rebuilding(struct jm_test_ctx *ctx, int shard_id,
				     uint32_t *target)
{
	struct pl_obj_shard	*shard;
	int			 i;

	jtc_for_each_layout_shard(ctx, shard, i) {
		if (shard->po_shard == shard_id && shard->po_rebuilding) {
			if (target != NULL)
				*target = shard->po_target;
			return true;
		}
	}

	return false;
}

static bool
jtc_has_shard_with_rebuilding_not_set(struct jm_test_ctx *ctx, int shard_id)
{
	struct pl_obj_shard	*shard;
	int			 i;

	jtc_for_each_layout_shard(ctx, shard, i) {
		if (shard->po_shard == shard_id && !shard->po_rebuilding)
			return true;
	}

	return false;
}

static bool
jtc_has_shard_target_rebuilding(struct jm_test_ctx *ctx, uint32_t shard_id,
			       uint32_t target)
{
	struct pl_obj_shard	*shard;
	int			 i;

	jtc_for_each_layout_shard(ctx, shard, i) {
		if (shard->po_shard == shard_id &&
		    shard->po_target == target &&
		    shard->po_rebuilding)
			return true;
	}
	return false;
}

static bool
jtc_has_shard_target_not_rebuilding(struct jm_test_ctx *ctx, uint32_t shard_id,
				    uint32_t target)
{
	struct pl_obj_shard	*shard;
	int			 i;

	jtc_for_each_layout_shard(ctx, shard, i) {
		if (shard->po_shard == shard_id &&
		    shard->po_target == target &&
		    !shard->po_rebuilding)
			return true;
	}
	return false;
}

static bool
jtc_has_shard_moving_to_target(struct jm_test_ctx *ctx, uint32_t shard_id,
			       uint32_t target)
{
	return jtc_has_shard_target_rebuilding(ctx, shard_id, target);
}

static bool
jtc_layout_has_target(struct jm_test_ctx *ctx, uint32_t id)
{
	struct pl_obj_shard	*shard;
	int			 i;

	jtc_for_each_layout_shard(ctx, shard, i) {
		if (shard->po_target == id)
			return true;
	}
	return false;
}

static bool
jtc_set_oid_with_shard_in_targets(struct jm_test_ctx *ctx, int *target_id,
				  int target_nr, int oc)
{
	int i, j;

	for (i = 0; i < 50; i++) {
		jtc_set_object_meta(ctx, oc, i + 1, UINT_MAX);
		assert_success(jtc_create_layout(ctx));
		for (j = 0; j < target_nr; j++)
			if (jtc_layout_has_target(ctx, target_id[j]))
				return true;
	}
	return false;
}

static void
jtc_snapshot_layout_targets(struct jm_test_ctx *ctx)
{
	struct pl_obj_shard *shard;
	int i;

	if (ctx->shard_targets)
		D_FREE(ctx->shard_targets);
	D_ALLOC_ARRAY(ctx->shard_targets, jtc_get_layout_nr(ctx));

	jtc_for_each_layout_shard(ctx, shard, i) {
		ctx->shard_targets[i] = shard->po_target;
	}
}

#define jtc_assert_scan_and_layout(ctx) do {\
	jtc_scan(ctx); \
	assert_success(jtc_create_layout(ctx)); \
} while (0)

/*
 * test that the layout has correct number of targets in rebuilding,
 * correct number of items from scan for find_reubild, find_reint, find_addition
 */
#define jtc_assert_rebuild_reint_new(ctx, l_rebuilding, s_rebuild, s_reint, \
				     s_new) \
	do {\
	if (l_rebuilding != jtc_get_layout_rebuild_count(&ctx)) \
		fail_msg("Expected %d rebuilding but found %d", l_rebuilding, \
		jtc_get_layout_rebuild_count(&ctx)); \
	if (s_rebuild != ctx.rebuild.out_nr) \
		fail_msg("Expected rebuild scan to return %d but found %d", \
		s_rebuild, ctx.rebuild.out_nr); \
	if (s_reint != ctx.reint.out_nr) \
		fail_msg("Expected reint scan to return %d but found %d", \
		s_reint, ctx.reint.out_nr); \
	if (s_new != ctx.new.out_nr) \
		fail_msg("Expected new scan to return %d but found %d", \
		s_new, ctx.new.out_nr); \
	} while (0)

#define UP	POOL_REINT
#define UPIN	POOL_ADD_IN
#define DOWN	POOL_EXCLUDE
#define DOWNOUT	POOL_EXCLUDE_OUT
#define DRAIN	POOL_DRAIN

/*
 * ------------------------------------------------
 * Begin Test cases using the jump map test context
 * ------------------------------------------------
 * ------------------------------------------------
 * Transition to DOWN state
 * ------------------------------------------------
 */
static void
down_to_target(void **state)
{
	struct jm_test_ctx	 ctx;

	jtc_init_with_layout(&ctx, 4, 1, 8, OC_RP_4G1, g_verbose);
	jtc_set_status_on_shard_target(&ctx, DOWN, 0);
	assert_success(jtc_create_layout(&ctx));

	jtc_scan(&ctx);
	assert_int_equal(ctx.rebuild.out_nr, 1);
	assert_int_equal(0, jtc_get_layout_bad_count(&ctx));
	jtc_fini(&ctx);
}


/*
 * ------------------------------------------------
 * End Test Cases
 * ------------------------------------------------
 */

static int
placement_test_setup(void **state)
{
	assert_success(obj_class_init());

	return pl_init();
}

static int
placement_test_teardown(void **state)
{
	pl_fini();
	obj_class_fini();

	return 0;
}

static void
one_server_is_added(void **state)
{
	struct jm_test_ctx	ctx;
	int			new_target_ids[] = {12, 13, 14, 15};

	jtc_init(&ctx, 4, 1, 3, OC_UNKNOWN, g_verbose);
	/* set oid so that it would place a shard in one of the last targets */
	assert_success(jtc_pool_map_extend(&ctx, 1, 1, 3));

	/* Make sure that the oid will place on the added target ids */
	is_true(jtc_set_oid_with_shard_in_targets(&ctx, new_target_ids,
						  ARRAY_SIZE(new_target_ids),
						  OC_RP_3G1));
	jtc_assert_scan_and_layout(&ctx);

	/* might have more than one because of other potential data movement,
	 * but should have at least 1
	 */
	is_true(ctx.new.out_nr > 0);
	assert_int_equal(0, ctx.rebuild.out_nr);
	assert_int_equal(0, ctx.reint.out_nr);

	assert_int_equal(ctx.new.out_nr, jtc_get_layout_rebuild_count(&ctx));

	jtc_fini(&ctx);
}

static void
drain_with_extra_domains(void **state)
{
	/*
	 * Drain all shards. There are plenty of extra domains to drain to.
	 * Number of targets should double, 1 DRAIN target
	 * (not "rebuilding") and the target being drained to (is "rebuilding")
	 */
	struct jm_test_ctx	 ctx;
	int			 i;
	const int		 shards_nr = 4; /* 2 x 2 */

	jtc_init_with_layout(&ctx, 4, 1, 2, OC_RP_3G1, false);
	assert_int_equal(3, jtc_get_layout_target_count(&ctx));

	/* drain all targets */
	jtc_set_status_on_all_shards(&ctx, DRAIN);
	jtc_assert_scan_and_layout(&ctx);

	assert_int_equal(6, jtc_get_layout_target_count(&ctx));

	jtc_fini(&ctx);
}



#define WIP(dsc, test) { "WIP PLACEMENT "STR(__COUNTER__)" ("#test"): " dsc, \
			  test, placement_test_setup, placement_test_teardown }
#define T(dsc, test) { "PLACEMENT "STR(__COUNTER__)" ("#test"): " dsc, test, \
			  placement_test_setup, placement_test_teardown }

static const struct CMUnitTest tests[] = {
	//T("my test", my_test),
	//T("down to target", down_to_target),
	//T("ons server is added", one_server_is_added)
	T("drain with extra domains", drain_with_extra_domains)
};

int
placement_tests_run(bool verbose)
{
	int rc = 0;

	g_verbose = verbose;

	rc += cmocka_run_group_tests_name("Jump Map Placement Tests", tests,
					  NULL, NULL);

	return rc;
}
