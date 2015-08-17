
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_atomic_t   lock;	//是否处于lock状态
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_t   wait;	//在等待这个锁的次数
#endif
} ngx_shmtx_sh_t;	//共享内存使用的共享内存的封装


typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
    ngx_atomic_t  *lock;	//lock指针，指向ngx_shmtx_sh_t->lock
#if (NGX_HAVE_POSIX_SEM)	//使用信号量时，信号量辅助处理lock等待操作
    ngx_atomic_t  *wait;	//wait指针，指向ngx_shmtx_sh_t->wait
    ngx_uint_t     semaphore;	//是否使用信号量
    sem_t          sem;		//信号量结构提
#endif
#else
    ngx_fd_t       fd;		//使用文件锁时的文件描述符
    u_char        *name;	//文件名称
#endif
    ngx_uint_t     spin;	//跟lock时等待时间相关
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr,
    u_char *name);
void ngx_shmtx_destroy(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
