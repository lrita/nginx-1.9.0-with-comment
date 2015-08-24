
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    void        **main_conf;//指针数组，数组中每个元素指向所有HTTP模块中create_main_conf方法产生的结构提
    void        **srv_conf; //指针数组，数组中每个元素指向所有HTTP模块中create_srv_conf方法产生的结构提
    void        **loc_conf; //指针数组，数组中每个元素指向所有HTTP模块中create_loc_conf方法产生的结构提
} ngx_http_conf_ctx_t;


typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);	//解析配置文件的http{...}内的内容前调用，如果返回失败，
    							//会终止进程

    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);	//解析完配置文件的http{...}内的内容后调用

    void       *(*create_main_conf)(ngx_conf_t *cf);	//当需要创建数据结构用户存储main级别(直属于http{...}块的配置)的全局
    							//配置项时,可以通过create_main_conf回调方法创建储存全局配置的结构体

    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);//解析完main配置项后调用

    void       *(*create_srv_conf)(ngx_conf_t *cf);	//当需要创建数据结构用户存储srv级别(直属于虚拟机server{...}块的配置)
    							//的配置项时,可以通过create_srv_conf回调方法创建储存srv配置的结构体
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);//用于合并srv和main级别下同名配置项，
    									  //可以main下的配置合并到srv配置中去。

    void       *(*create_loc_conf)(ngx_conf_t *cf);	//当需要创建数据结构用户存储loc级别(直属于location{...}块的配置)的全
    							//局配置项时,可以通过create_loc_conf回调方法创建储存全局配置的结构体
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);//用于合并srv和loc级别下同名配置项
} ngx_http_module_t;


#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

#define NGX_HTTP_MAIN_CONF        0x02000000	//配置可以出现在http{}块内
#define NGX_HTTP_SRV_CONF         0x04000000	//配置可以出现在http{}块内的server{}块里
#define NGX_HTTP_LOC_CONF         0x08000000	//配置可以出现在http{}块内的location{}块里
#define NGX_HTTP_UPS_CONF         0x10000000	//配置可以出现在http{}块内的upstream{}块里
#define NGX_HTTP_SIF_CONF         0x20000000	//配置可以出现在http{}块内的server{}块里的if{}块中，用于rewrite
#define NGX_HTTP_LIF_CONF         0x40000000	//配置可以出现在http{}块内的location{}块里if{}块中，用于rewrite
#define NGX_HTTP_LMT_CONF         0x80000000	//配置可以出现在http{}块内的limit_except{}块中


#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)


#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
