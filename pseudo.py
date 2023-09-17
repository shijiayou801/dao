from zlib import crc64

NEW     = 0
DRAIN   = 1
UPIN    = 2
UP      = 3
DOWN    = 4
DOWNOUT = 5
EXCLUDE = 6

used = {}

def remap(remap_list):
    pass
def jump_hash(key, nr_buckets):
    pass

def need_remap(target, allow_status):
    return target.status & allow_status == 0

def get_non_new_count(items):
    count = len(items)
    for item in items:
        if item.status == NEW:
            count -= 1
    return count

def choose_target(key, targets, used):
    key = crc64(key, 0)
    count = get_non_new_count(targets)
    select = jump_hash(key, count)
    
    while True:
        select = select % count
        target = targets[select]
        
        if used[target] == False:
            used[target] = True
            return target
        
        select += 1

def choose_subdomain(key, domains):
    fail_num = 0
    count = get_non_new_count(domains)
    
    while True:
        select = jump_hash(key, count)
        domain = domains[select]

        if used[domain] == False:
            used[domain] = True
            return domains[select]
        
        key = crc64(key, fail_num)
        fail_num += 1

def get_target(key, shard_num, domain):
    if domain.is_last_level:
        return choose_target(key, domain.targets)

    domain = choose_subdomain(key, domain.subdomains)
    key = crc64(key, domain.id)

    return get_target(key, shard_num, domain)

def jump_get_layout(jump_map, oid, allow_status, remap_list):
    key = oid.high ^ oid.low
    layout = {}

    for shard_index in range(0, jump_map.replica_size):
        shard_key = crc64(key, shard_index)
        target = get_target(shard_key, shard_index, jump_map.root)
        layout[shard_index] = target
        if need_remap(target, allow_status):
            remap_list.append({shard_index, target})

    if remap_list.count() > 0:
        remap(remap_list)
        
    return layout

# IO
def jump_map_obj_place(jump_map, oid):
    flag = UPIN | DRAIN
    layout1 = jump_get_layout(jump_map, oid, flag, None)

    if jump_map.is_adding:     # target in layout1 == NEW
        flag |= NEW
    if jump_map.is_extending:  # target in layout1 == UP | DRAIN
        flag |= UP
    
    layout2 = jump_get_layout(jump_map, oid, flag, None)
    return layout1.extend(layout2)

# Fail: find where EXCLUDED target's objects should relocate
# Drain: find where DRAIN target's objects should relocate
def jump_map_obj_find_rebuild(jump_map, oid):
    remap_list = {}
    jump_get_layout(jump_map, oid, UPIN, remap_list)
    return remap_list

# Add: find what objects the NEW targets should pull
def jump_map_obj_find_addition(jump_map, oid):
    layout1 = jump_get_layout(jump_map, oid, UPIN, None)
    layout2 = jump_get_layout(jump_map, oid, UPIN | NEW, None)
    return layout1.diff(layout2)

def jump_map_obj_find_reint(jump_map, oid):
    layout1 = jump_get_layout(jump_map, oid, UPIN | DRAIN | DOWN, None)
    layout2 = jump_get_layout(jump_map, oid, UPIN | DRAIN | DOWN | UP, None)
    return layout1.diff(layout2)
