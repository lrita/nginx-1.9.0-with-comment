
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONF_FILE_H_INCLUDED_
#define _NGX_CONF_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 *        AAAA  number of arguments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define NGX_CONF_NOARGS      0x00000001	//配置项不携带参数
#define NGX_CONF_TAKE1       0x00000002	//配置项必须携带1个参数
#define NGX_CONF_TAKE2       0x00000004	//配置项必须携带2个参数
#define NGX_CONF_TAKE3       0x00000008
#define NGX_CONF_TAKE4       0x00000010
#define NGX_CONF_TAKE5       0x00000020
#define NGX_CONF_TAKE6       0x00000040
#define NGX_CONF_TAKE7       0x00000080

#define NGX_CONF_MAX_ARGS    8

#define NGX_CONF_TAKE12      (NGX_CONF_TAKE1|NGX_CONF_TAKE2)	//配置项可以携带1个或2个参数
#define NGX_CONF_TAKE13      (NGX_CONF_TAKE1|NGX_CONF_TAKE3)

#define NGX_CONF_TAKE23      (NGX_CONF_TAKE2|NGX_CONF_TAKE3)

#define NGX_CONF_TAKE123     (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3)
#define NGX_CONF_TAKE1234    (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3   \
                              |NGX_CONF_TAKE4)

#define NGX_CONF_ARGS_NUMBER 0x000000ff	//目前无意义
#define NGX_CONF_BLOCK       0x00000100	//配置项定义一种新的{}块，如http、server
#define NGX_CONF_FLAG        0x00000200	//配置项的参数只能是一个 on或者off
#define NGX_CONF_ANY         0x00000400	//不验证参数的个数
#define NGX_CONF_1MORE       0x00000800	//配置项携带的参数必须超过1个
#define NGX_CONF_2MORE       0x00001000	//配置项携带的参数必须超过2个
#define NGX_CONF_MULTI       0x00000000  /* compatibility */

#define NGX_DIRECT_CONF      0x00010000	//一般由NGX_CORE_MODULE类型的核心模块使用，仅与下面的NGX_MAIN_CONF同时
					//设置，表示模块需要解析不属于任何{}内的全局配置项。可以出现在配置文件
					//的最外层，例如master_process、daemon

#define NGX_MAIN_CONF        0x01000000	//配置想可以出现在全局配置中，不属于任何{}，http、events等
#define NGX_ANY_CONF         0x0F000000	//预留项



#define NGX_CONF_UNSET       -1
#define NGX_CONF_UNSET_UINT  (ngx_uint_t) -1
#define NGX_CONF_UNSET_PTR   (void *) -1
#define NGX_CONF_UNSET_SIZE  (size_t) -1
#define NGX_CONF_UNSET_MSEC  (ngx_msec_t) -1


#define NGX_CONF_OK          NULL
#define NGX_CONF_ERROR       (void *) -1

#define NGX_CONF_BLOCK_START 1
#define NGX_CONF_BLOCK_DONE  2
#define NGX_CONF_FILE_DONE   3

#define NGX_CORE_MODULE      0x45524F43  /* "CORE" */
#define NGX_CONF_MODULE      0x464E4F43  /* "CONF" */


#define NGX_MAX_CONF_ERRSTR  1024


struct ngx_command_s {
    ngx_str_t             name;	//配置项名，如'gzip'
    ngx_uint_t            type;	//配置项类型(有几个参数或者可以在什么地方出现等)，如出现在server{}、location{}，以及可以
    				//携带及测参数 参见NGX_MAIN_CONF等宏
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);	//出现了name中制定的配置项后，将会调用set
    										//方法处理配置项参数.这个可以使用nginx预设
    										//的14个解析配置方法，也可以使用自定义的cf
    										//参数保存了从配置文件中读取到的原始字符串
    										//以及相关的一些信息，其中有一个args字段，
    										//它表示配置指令以及该配置指令的参数，
    										//ngx_str_t类型。conf就是定义的存储这个配置
    										//值的结构体，在使用的时候需要转换成自己使用
    										//的类型。
    ngx_uint_t            conf;	//在配置文件中的偏移量，它的取值范围是：NGX_HTTP_MAIN_CONF_OFFSET,NGX_HTTP_SRV_CONF_OFFSET
    				//NGX_HTTP_LOC_CONF_OFFSET.因为有可能模块同时会有main，srv，loc三种配置结构体，但是这个配置
    				//项解析完后要放在哪个结构体内呢？当设置为0时，就是NGX_HTTP_MAIN_CONF_OFFSET

    ngx_uint_t            offset;	//表示当前配置项在整个存储配置项的结构体中的偏移位置.可以使用offsetof(test_stru, b)
    					//来获取.对于有些配置项，它的值不需要保存，就可以设置为0

    void                 *post;	//命令处理完后的回调指针，对于set的14种预设的解析配置方法， 可能的结构有：
    				//ngx_conf_post_t,ngx_conf_enum_t,ngx_conf_bitmask_t,null
};

#define ngx_null_command  { ngx_null_string, 0, NULL, 0, 0, NULL }	//空命令,一般作为数组结束标志


struct ngx_open_file_s {
    ngx_fd_t              fd;
    ngx_str_t             name;

    void                (*flush)(ngx_open_file_t *file, ngx_log_t *log);
    void                 *data;
};


#define NGX_MODULE_V1          0, 0, 0, 0, 0, 0, 1
#define NGX_MODULE_V1_PADDING  0, 0, 0, 0, 0, 0, 0, 0

//ngx_module_s是模块的定义
struct ngx_module_s {
    ngx_uint_t            ctx_index;	//分类的模块计数器
					//nginx模块可以分为四种：core、event、http和mail
					//每个模块都会各自计数，ctx_index就是每个模块在其所属类组的计数
    					//对于一类模块（由下面的type成员决定类别）而言，ctx_index标示当
    					//前模块在这类模块中的序号。这个成员常常是由管理这类模块的一个
    					//nginx核心模块设置的，对于所有的HTTP模块而言，ctx_index是由核
    					//心模块ngx_http_module设置的。

    ngx_uint_t            index;	//index表示当前模块在ngx_modules数组中的序号。Nginx启动的时候
    					//会根据ngx_modules数组设置各个模块的index值

    ngx_uint_t            spare0;	//spare系列的保留变量，暂未使用
    ngx_uint_t            spare1;
    ngx_uint_t            spare2;
    ngx_uint_t            spare3;

    ngx_uint_t            version;	//nginx模块版本

    void                 *ctx;		//模块的上下文，不同种类的模块有不同的上下文，因此实现了四种结构体
    					//模块上下文，每个模块有不同模块上下文,每个模块都有自己的特性，而
    					//ctx会指向特定类型模块的公共接口
    					//比如，在HTTP模块中，ctx需要指向ngx_http_module_t结构体，这是HTTP模块要求的。

    ngx_command_t        *commands;	//命令定义地址 模块的指令集 每一个指令在源码中对应着一个ngx_command_t
    					//结构变量 将处理nginx.conf中的配置项

    ngx_uint_t            type;		//标示该模块的类型，和ctx是紧密相关的。它的取值范围是以下几种:
    					//NGX_HTTP_MODULE,NGX_CORE_MODULE,NGX_CONF_MODULE,
    					//NGX_EVENT_MODULE,NGX_MAIL_MODULE

    //下面7个函数是nginx在启动，停止过程中的7个执行点 如果不需要在这个点做任何操作，可以置为NULL
    ngx_int_t           (*init_master)(ngx_log_t *log);		//初始化master时的调用，现版本这个点并没有被使用，置为NULL
    ngx_int_t           (*init_module)(ngx_cycle_t *cycle);	//初始化模块时的调用
    ngx_int_t           (*init_process)(ngx_cycle_t *cycle);	//初始化进程时的调用
    ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);	//初始化线程时的调用，现版本这个点并没有被使用，置为NULL
    void                (*exit_thread)(ngx_cycle_t *cycle);	//退出线程时的调用，现版本这个点并没有被使用，置为NULL
    void                (*exit_process)(ngx_cycle_t *cycle);	//退出进程时的调用
    void                (*exit_master)(ngx_cycle_t *cycle);	//退出master时的调用

    //保留字段，无用，可以使用NGX_MODULE_V1_PADDING来替换
    uintptr_t             spare_hook0;
    uintptr_t             spare_hook1;
    uintptr_t             spare_hook2;
    uintptr_t             spare_hook3;
    uintptr_t             spare_hook4;
    uintptr_t             spare_hook5;
    uintptr_t             spare_hook6;
    uintptr_t             spare_hook7;
};


typedef struct {
    ngx_str_t             name;
    void               *(*create_conf)(ngx_cycle_t *cycle);
    char               *(*init_conf)(ngx_cycle_t *cycle, void *conf);
} ngx_core_module_t;


typedef struct {
    ngx_file_t            file;
    ngx_buf_t            *buffer;
    ngx_uint_t            line;
} ngx_conf_file_t;


typedef char *(*ngx_conf_handler_pt)(ngx_conf_t *cf,
    ngx_command_t *dummy, void *conf);


struct ngx_conf_s {
    char                 *name;
    ngx_array_t          *args;

    ngx_cycle_t          *cycle;
    ngx_pool_t           *pool;
    ngx_pool_t           *temp_pool;
    ngx_conf_file_t      *conf_file;
    ngx_log_t            *log;

    void                 *ctx;
    ngx_uint_t            module_type;
    ngx_uint_t            cmd_type;

    ngx_conf_handler_pt   handler;
    char                 *handler_conf;
};


typedef char *(*ngx_conf_post_handler_pt) (ngx_conf_t *cf,
    void *data, void *conf);

typedef struct {
    ngx_conf_post_handler_pt  post_handler;
} ngx_conf_post_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} ngx_conf_deprecated_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    ngx_int_t                 low;
    ngx_int_t                 high;
} ngx_conf_num_bounds_t;


typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                value;
} ngx_conf_enum_t;


#define NGX_CONF_BITMASK_SET  1

typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                mask;
} ngx_conf_bitmask_t;



char * ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data);
char *ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data);


#define ngx_get_conf(conf_ctx, module)  conf_ctx[module.index]



#define ngx_conf_init_value(conf, default)                                   \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }

#define ngx_conf_init_ptr_value(conf, default)                               \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }

#define ngx_conf_init_uint_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_size_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_init_msec_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }

#define ngx_conf_merge_value(conf, prev, default)                            \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = (prev == NGX_CONF_UNSET_PTR) ? default : prev;                \
    }

#define ngx_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = (prev == NGX_CONF_UNSET_UINT) ? default : prev;               \
    }

#define ngx_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = (prev == NGX_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define ngx_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_size_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = (prev == NGX_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define ngx_conf_merge_off_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }

#define ngx_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define ngx_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }


char *ngx_conf_param(ngx_conf_t *cf);
char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);
char *ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_int_t ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name,
    ngx_uint_t conf_prefix);
ngx_open_file_t *ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name);
void ngx_cdecl ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf,
    ngx_err_t err, const char *fmt, ...);


char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


extern ngx_uint_t     ngx_max_module;
extern ngx_module_t  *ngx_modules[];


#endif /* _NGX_CONF_FILE_H_INCLUDED_ */
