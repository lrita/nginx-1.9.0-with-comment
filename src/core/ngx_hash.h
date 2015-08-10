
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void             *value;
    u_short           len;
    u_char            name[1];
} ngx_hash_elt_t;


typedef struct {
    ngx_hash_elt_t  **buckets;
    ngx_uint_t        size;
} ngx_hash_t;


typedef struct {
    ngx_hash_t        hash;
    void             *value;
} ngx_hash_wildcard_t;


typedef struct {
    ngx_str_t         key;
    ngx_uint_t        key_hash;
    void             *value;
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


//nginx提供该类型的作用，在于提供一个方便的容器包含三个类型的hash表，
//当有包含通配符的和不包含通配符的一组key构建hash表以后，以一种方便的
//方式来查询，你不需要再考虑一个key到底是应该到哪个类型的hash表里去查了。
//构造这样一组合hash表的时候，首先定义一个该类型的变量，再分别构造其包含的三个子hash表即可
typedef struct {
    ngx_hash_t            hash;		//一个普通hash表
    ngx_hash_wildcard_t  *wc_head;	//一个包含前向通配符的hash表
    ngx_hash_wildcard_t  *wc_tail;	//一个包含后向通配符的hash表
} ngx_hash_combined_t;


//1.ngx_hash_t不像其他的hash表的实现，可以插入删除元素，它只能一次初始化，
//就构建起整个hash表以后，既不能再删除，也不能在插入元素了。

//2.ngx_hash_t的开链并不是真的开了一个链表，实际上是开了一段连续的存储空间，
//几乎可以看做是一个数组。这是因为ngx_hash_t在初始化的时候，会经历一次预
//计算的过程，提前把每个桶里面会有多少元素放进去给计算出来，这样就提前知
//道每个桶的大小了。那么就不需要使用链表，一段连续的存储空间就足够了。这也从一定程度上节省了内存的使用
typedef struct {
    ngx_hash_t       *hash;		//该字段如果为NULL，那么调用完初始化函数后，该字段指向新创建出来的hash表。
    					//如果该字段不为NULL，那么在初始的时候，所有的数据被插入了这个字段所指的hash表中

    ngx_hash_key_pt   key;		//指向从字符串生成hash值的hash函数。
    					//nginx的源代码中提供了默认的实现函数ngx_hash_key_lc

    ngx_uint_t        max_size;		//hash表中的桶的个数。该字段越大，元素存储时冲突的可能性越小，
    					//每个桶中存储的元素会更少，则查询起来的速度更快。当然，这个值越大，
    					//越造成内存的浪费也越大，(实际上也浪费不了多少)

    ngx_uint_t        bucket_size;	//每个桶的最大限制大小，单位是字节。如果在初始化一个hash表的时候，
    					//发现某个桶里面无法存的下所有属于该桶的元素，则hash表初始化失败。

    char             *name;		//该hash表的名字
    ngx_pool_t       *pool;		//该hash表分配内存使用的pool
    ngx_pool_t       *temp_pool;	//该hash表使用的临时pool，在初始化完成以后，该pool可以被释放和销毁掉
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


//在构建一个ngx_hash_wildcard_t的时候，需要对通配符的哪些key进行预处理。
//这个处理起来比较麻烦。而当有一组key，这些里面既有无通配符的key，也有包
//含通配符的key的时候。我们就需要构建三个hash表，一个包含普通的key的hash
//表，一个包含前向通配符的hash表，一个包含后向通配符的hash表（或者也可以
//把这三个hash表组合成一个ngx_hash_combined_t）。在这种情况下，为了让大家
//方便的构造这些hash表，nginx提供给了此辅助类型
typedef struct {
    ngx_uint_t        hsize;		//将要构建的hash表的桶的个数。对于使用这个结构中包含
    					//的信息构建的三种类型的hash表都会使用此参数

    ngx_pool_t       *pool;		//构建这些hash表使用的pool
    ngx_pool_t       *temp_pool;	//在构建这个类型以及最终的三个hash表过程中可能用到临时pool。
    					//该temp_pool可以在构建完成以后，被销毁掉。这里只是存放临时
    					//的一些内存消耗

    ngx_array_t       keys;		//存放所有非通配符key的数组
    ngx_array_t      *keys_hash;	//这是个二维数组，第一个维度代表的是bucket的编号，那么keys_hash[i]
    					//中存放的是所有的key算出来的hash值对hsize取模以后的值为i的key。
    					//假设有3个key,分别是key1,key2和key3假设hash值算出来以后对hsize取模
    					//的值都是i，那么这三个key的值就顺序存放在keys_hash[i][0],
    					//keys_hash[i][1], keys_hash[i][2]。该值在调用的过程中用来保存和检测
    					//是否有冲突的key值，也就是是否有重复

    ngx_array_t       dns_wc_head;	//放前向通配符key被处理完成以后的值。比如：“*.abc.com” 被处理完成以
    					//后，变成 “com.abc.” 被存放在此数组中

    ngx_array_t      *dns_wc_head_hash;	//该值在调用的过程中用来保存和检测是否有冲突的前向通配符的key值，也就
    					//是是否有重复

    ngx_array_t       dns_wc_tail;	//存放后向通配符key被处理完成以后的值。比如：“mail.xxx.*” 被处理完成
    					//以后，变成 “mail.xxx.” 被存放在此数组中

    ngx_array_t      *dns_wc_tail_hash;	//该值在调用的过程中用来保存和检测是否有冲突的后向通配符的key值，也就
    					//是是否有重复
} ngx_hash_keys_arrays_t;
//在定义一个这个类型的变量，并对字段pool和temp_pool赋值以后，就可以调用函数ngx_hash_add_key把所有的key加入到
//这个结构中了，该函数会自动实现普通key，带前向通配符的key和带后向通配符的key的分类和检查，并将这个些值存放到
//对应的字段中去， 然后就可以通过检查这个结构体中的keys、dns_wc_head、dns_wc_tail三个数组是否为空，来决定是否
//构建普通hash表，前向通配符hash表和后向通配符hash表了（在构建这三个类型的hash表的时候，可以分别使用keys、
//dns_wc_head、dns_wc_tail三个数组）


typedef struct {
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
