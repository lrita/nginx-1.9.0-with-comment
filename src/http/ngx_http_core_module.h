
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CORE_H_INCLUDED_
#define _NGX_HTTP_CORE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif


#define NGX_HTTP_GZIP_PROXIED_OFF       0x0002
#define NGX_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define NGX_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define NGX_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define NGX_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define NGX_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define NGX_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define NGX_HTTP_GZIP_PROXIED_AUTH      0x0100
#define NGX_HTTP_GZIP_PROXIED_ANY       0x0200


#define NGX_HTTP_AIO_OFF                0
#define NGX_HTTP_AIO_ON                 1
#define NGX_HTTP_AIO_THREADS            2


#define NGX_HTTP_SATISFY_ALL            0
#define NGX_HTTP_SATISFY_ANY            1


#define NGX_HTTP_LINGERING_OFF          0
#define NGX_HTTP_LINGERING_ON           1
#define NGX_HTTP_LINGERING_ALWAYS       2


#define NGX_HTTP_IMS_OFF                0
#define NGX_HTTP_IMS_EXACT              1
#define NGX_HTTP_IMS_BEFORE             2


#define NGX_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define NGX_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define NGX_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


typedef struct ngx_http_location_tree_node_s  ngx_http_location_tree_node_t;
typedef struct ngx_http_core_loc_conf_s  ngx_http_core_loc_conf_t;


typedef struct {
    union {
        struct sockaddr        sockaddr;
        struct sockaddr_in     sockaddr_in;
#if (NGX_HAVE_INET6)
        struct sockaddr_in6    sockaddr_in6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
        struct sockaddr_un     sockaddr_un;
#endif
        u_char                 sockaddr_data[NGX_SOCKADDRLEN];
    } u;

    socklen_t                  socklen;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HTTP_SPDY)
    unsigned                   spdy:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned                   ipv6only:1;
#endif
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (NGX_HAVE_SETFIB)
    int                        setfib;
#endif
#if (NGX_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
    ngx_uint_t                 deferred_accept;
#endif

    u_char                     addr[NGX_SOCKADDR_STRLEN + 1];
} ngx_http_listen_opt_t;


//这个结构是定义了HTTP模块处理用户请求的11个阶段
typedef enum {
    NGX_HTTP_POST_READ_PHASE = 0,	//在接收到完整的HTTP头部后处理的HTTP阶段

    NGX_HTTP_SERVER_REWRITE_PHASE,	//在还没有查询到URI匹配的location前，这时rewrite重写URL也作为一个
    					//独立的HTTP阶段

    NGX_HTTP_FIND_CONFIG_PHASE,		//根据URI寻找匹配的location，这个阶段通常由ngx_http_core_module模块
    					//实现，不建议其他HTTP模块重新改写这一阶段的行为

    NGX_HTTP_REWRITE_PHASE,		//在NGX_HTTP_FIND_CONFIG_PHASE阶段之后重写URL的意义与
    					//NGX_HTTP_SERVER_REWRITE_PHASE显然是不同的，因为这两者会导致查询到不
    					//同的location块

    NGX_HTTP_POST_REWRITE_PHASE,	//这一阶段是用于在rewrite重写URL后重新跳到NGX_HTTP_FIND_CONFIG_PHASE阶
    					//段，找到与新的URL匹配的location。所以，这一阶段是无法由第三方HTTP模
    					//块处理的，而仅由ngx_http_core_module模块使用。

    NGX_HTTP_PREACCESS_PHASE,		//处理NGX_HTTP_ACCESS_PHASE阶段前，HTTP模块可以介入处理的阶段

    NGX_HTTP_ACCESS_PHASE,		//这个阶段用于让HTTP模块判断是否允许这个请求访问Nginx服务器
    NGX_HTTP_POST_ACCESS_PHASE,		//当NGX_HTTP_ACCESS_PHASE阶段中HTTP模块的handler处理方法返回不允许访问
    					//的错误码时(实际是NGX_HTTP_FORBIDDEN和NGX_HTTP_UNAUTHORIZED)，这个阶
    					//段将负责构造拒绝服务用户的响应。所以，这个阶段实际上用户给NGX_HTTP_ACCESS_PHASE
    					//阶段收尾。

    NGX_HTTP_TRY_FILES_PHASE,		//这个阶段完全是为了try_files配置而设立的。当HTTP请求访问静态资源文件
    					//时，try_files配置项可以使这个请求顺序地访问多个静态文件资源，如果一
    					//次访问失败，则继续访问try_files中指定的下一个静态资源。另外，这个功
    					//能完全是在NGX_HTTP_TRY_FILES_PHASE阶段中实现的。

    NGX_HTTP_CONTENT_PHASE,		//用于处理HTTP请求内容的阶段。这个是大部分HTTP模块最喜欢介入的阶段。

    NGX_HTTP_LOG_PHASE			//处理完请求后记录日志的阶段。例如，ngx_http_log_module模块就在这个阶
	    				//段中加入了一个handle处理方法，使得每个HTTP请求处理完毕后都会记录
	    				//access_log日志
} ngx_http_phases;

typedef struct ngx_http_phase_handler_s  ngx_http_phase_handler_t;

// 一个HTTP处理阶段中的checker检查方法，仅可以由HTTP框架实现，以此控制HTTP请求的处理流程
typedef ngx_int_t (*ngx_http_phase_handler_pt)(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);

struct ngx_http_phase_handler_s {
    ngx_http_phase_handler_pt  checker;	//在处理到某一个HTTP阶段时，HTTP框架将会在checker方法已实现的前提下首先
    					//调用checker方法来处理请求，而不会直接接调用任何阶段汇总的handler方法
    					//。只有在checker方法中才会去调用handler方法。因此，事实上所有的checker
    					//方法都是由框架中的ngx_http_core_module模块实现的，且普通的HTTP模块无
    					//法重定义checker方法

    ngx_http_handler_pt        handler;	//除ngx_http_core_module模块以外的HTTP模块，只能通过定义handler方法才能
    					//介入某一个HTTP处理阶段以处理请求

    ngx_uint_t                 next;	//next的设计使得处理阶段不必按照顺序依次执行，既可以向后跳跃数个阶段继
    					//续执行，也可以跳跃到之前曾经执行过的某个阶段重新执行。通常，next表示
    					//下一个处理阶段中的第一个ngx_http_phase_handler_t处理方法
};


typedef struct {
    ngx_http_phase_handler_t  *handlers;		//handlers是由ngx_http_phase_handler_t构成的数组首地址，
    							//它表示一个请求可能经历的所有ngx_http_handler_pt处理方法

    ngx_uint_t                 server_rewrite_index;	//表示NGX_HTTP_REWRITE_PHASE阶段第一个ngx_http_phase_handler_t
    							//处理方法在handlers数组中的序号，用于在执行HTTP请求的
    							//任何阶段中快速跳转到NGX_HTTP_SERVER_REWRITE_PHASE阶段
    							//处理请求

    ngx_uint_t                 location_rewrite_index;	//表示NGX_HTTP_REWRITE_PHASE阶段第一个ngx_http_phase_handler_t
    							//处理方法在handlers数组中的序号，用于在执行HTTP请求的
    							//任何阶段中快速跳转到NGX_HTTP_SERVER_REWRITE_PHASE阶段
    							//处理请求
} ngx_http_phase_engine_t;


typedef struct {
    ngx_array_t                handlers;	//保存着每一个HTTP模块初始化时添加到当前阶段的处理方法
} ngx_http_phase_t;


typedef struct {
    ngx_array_t                servers;         /* ngx_http_core_srv_conf_t */

    ngx_http_phase_engine_t    phase_engine;	//由下面各阶段处理方法构成的phases数组构建的阶段引擎才是流水式
    						//处理HTTP请求的实际数据结构

    ngx_hash_t                 headers_in_hash;

    ngx_hash_t                 variables_hash;

    ngx_array_t                variables;       /* ngx_http_variable_t */
    ngx_uint_t                 ncaptures;

    ngx_uint_t                 server_names_hash_max_size;	//服务器名称哈希表的最大值
    ngx_uint_t                 server_names_hash_bucket_size;	//服务器名称哈希表桶的最大值

    ngx_uint_t                 variables_hash_max_size;		//变量哈希表的大小
    ngx_uint_t                 variables_hash_bucket_size;	//变量哈希表桶的大小

    ngx_hash_keys_arrays_t    *variables_keys;

    ngx_array_t               *ports;

    ngx_uint_t                 try_files;       /* unsigned  try_files:1 */

    ngx_http_phase_t           phases[NGX_HTTP_LOG_PHASE + 1];	//用于在HTTP框架初始化时帮助各个HTTP模块在任意
    								//阶段添加HTTP处理方法，它是一个由11个成员组成
    								//的ngx_http_phase_t数组，其中每一个ngx_http_phase_t
    								//结构体对应一个HTTP阶段。在HTTP框架初始化完毕
    								//后，运行过程中phases数组是无用的。
} ngx_http_core_main_conf_t;


typedef struct {
    /* array of the ngx_http_server_name_t, "server_name" directive */
    ngx_array_t                 server_names;

    /* server ctx */
    ngx_http_conf_ctx_t        *ctx;

    ngx_str_t                   server_name;

    size_t                      connection_pool_size;		//为每个请求分配的内存池大小
    size_t                      request_pool_size;		//为每个请求分配的内存池大小
    size_t                      client_header_buffer_size;	//用于指定来自客户端请求头的headerbuffer大小。对于大多数请求
    								//，1K的缓冲区大小已经足够，如果自定义了消息头或有更大的Cookie，
    								//可以增加缓冲区大小

    ngx_bufs_t                  large_client_header_buffers;	//用来指定客户端请求中较大的消息头的缓存最大数量和大小， 第
    								//一个为buffer个数，第二个为buffer大小

    ngx_msec_t                  client_header_timeout;		//指令指定读取客户端请求头标题的超时时间。这里的超时是指一个
    								//请求头没有进入读取步骤，如果连接超过这个时间而客户端没有任
    								//何响应，Nginx将返回一个”Request time out” (408)错误。

    ngx_flag_t                  ignore_invalid_headers;
    ngx_flag_t                  merge_slashes;
    ngx_flag_t                  underscores_in_headers;		//是否允许在header的字段中带下划线

    unsigned                    listen:1;
#if (NGX_PCRE)
    unsigned                    captures:1;
#endif

    ngx_http_core_loc_conf_t  **named_locations;
} ngx_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (NGX_PCRE)
    ngx_http_regex_t          *regex;
#endif
    ngx_http_core_srv_conf_t  *server;   /* virtual name server conf */
    ngx_str_t                  name;
} ngx_http_server_name_t;


typedef struct {
     ngx_hash_combined_t       names;

     ngx_uint_t                nregex;
     ngx_http_server_name_t   *regex;
} ngx_http_virtual_names_t;


struct ngx_http_addr_conf_s {
    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;

    ngx_http_virtual_names_t  *virtual_names;

#if (NGX_HTTP_SSL)
    unsigned                   ssl:1;
#endif
#if (NGX_HTTP_SPDY)
    unsigned                   spdy:1;
#endif
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;
    ngx_http_addr_conf_t       conf;
} ngx_http_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    ngx_http_addr_conf_t       conf;
} ngx_http_in6_addr_t;

#endif


typedef struct {
    /* ngx_http_in_addr_t or ngx_http_in6_addr_t */
    void                      *addrs;
    ngx_uint_t                 naddrs;
} ngx_http_port_t;


typedef struct {
    ngx_int_t                  family;	//socket 地址家族
    in_port_t                  port;	//监听端口
    ngx_array_t                addrs;   /* array of ngx_http_conf_addr_t *///监听的端口下对应着的所有ngx_http_conf_addr_t地址
} ngx_http_conf_port_t;


typedef struct {
    ngx_http_listen_opt_t      opt;

    ngx_hash_t                 hash;
    ngx_hash_wildcard_t       *wc_head;
    ngx_hash_wildcard_t       *wc_tail;

#if (NGX_PCRE)
    ngx_uint_t                 nregex;
    ngx_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    ngx_http_core_srv_conf_t  *default_server;
    ngx_array_t                servers;  /* array of ngx_http_core_srv_conf_t */
} ngx_http_conf_addr_t;


typedef struct {
    ngx_int_t                  status;		//错误代码 404 403
    ngx_int_t                  overwrite;	//是否应304代替
    ngx_http_complex_value_t   value;		//存储error_page指向的文件
    ngx_str_t                  args;		//额外参数
} ngx_http_err_page_t;	//error_page 数据结构


typedef struct {
    ngx_array_t               *lengths;
    ngx_array_t               *values;
    ngx_str_t                  name;

    unsigned                   code:10;
    unsigned                   test_dir:1;
} ngx_http_try_file_t;


struct ngx_http_core_loc_conf_s {
    ngx_str_t     name;          /* location name */

#if (NGX_PCRE)
    ngx_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (NGX_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
#if (NGX_HTTP_DEGRADATION)
    unsigned      gzip_disable_degradation:2;
#endif
#endif

    ngx_http_location_tree_node_t   *static_locations;
#if (NGX_PCRE)
    ngx_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    ngx_http_handler_pt  handler;					//该location执行handler

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    ngx_str_t     root;                    /* root, alias */
    ngx_str_t     post_action;

    ngx_array_t  *root_lengths;
    ngx_array_t  *root_values;

    ngx_array_t  *types;
    ngx_hash_t    types_hash;
    ngx_str_t     default_type;						//某个文件在标准MIME视图没有指定的情况下的默认MIME
    									//类型

    off_t         client_max_body_size;    /* client_max_body_size */	//指令指定允许客户端连接的最大请求实体大小，它出现
    						//在请求头部的Content-Length字段。如果请求大于指定的值，客户端将收到一个"Request Entity Too Large"(413)
    						//错误。记住，浏览器并不知道怎样显示这个错误。
    off_t         directio;                /* directio *///该指令允许使用标志O_DIRECT（FreeBSD，Linux）
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size *///指定连接请求实体的缓冲区大小。如果连接请求超过缓存
    						//区指定的值，那么这些请求实体的整体或部分将尝试写入一个临时文件。默认值为两
    						//个内存分页大小值，根据平台的不同，可能是8k或16k。当请求头中的Content-Length
    						//字段小于指定的buffer size，那么Nginx将使用较小的一个，所以nginx并不总是为每
    						//一个请求分配这个buffer size大小的buffer。 
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        limit_rate;              /* limit_rate */
    size_t        limit_rate_after;        /* limit_rate_after */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */

    ngx_msec_t    client_body_timeout;     /* client_body_timeout */	//读取请求实体的超时时间。这里的超时是指一个请求实体
    						//没有进入读取步骤，如果连接超过这个时间而客户端没有任何响应，Nginx将返回一个
    						//"Request time out" (408)错误
    ngx_msec_t    send_timeout;            /* send_timeout */
    ngx_msec_t    keepalive_timeout;       /* keepalive_timeout */	//指定了客户端与服务器长连接的超时时间
    ngx_msec_t    lingering_time;          /* lingering_time */
    ngx_msec_t    lingering_timeout;       /* lingering_timeout */
    ngx_msec_t    resolver_timeout;        /* resolver_timeout *///解析超时时间

    ngx_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout *///指定了应答头中Keep-Alive: timeout=time的time值，这个值可以
    						//使一些浏览器知道什么时候关闭连接，以便服务器不用重复关闭，如果不指定这个参数，
    						//nginx不会在应答头中发送Keep-Alive信息.

    ngx_uint_t    keepalive_requests;      /* keepalive_requests */
    ngx_uint_t    keepalive_disable;       /* keepalive_disable */
    ngx_uint_t    satisfy;                 /* satisfy */
    ngx_uint_t    lingering_close;         /* lingering_close */
    ngx_uint_t    if_modified_since;       /* if_modified_since */
    ngx_uint_t    max_ranges;              /* max_ranges */
    ngx_uint_t    client_body_in_file_only; /* client_body_in_file_only *///始终存储一个连接请求实体到一个文件即使它只有0
    						//字节。注意：如果这个指令打开，那么一个连接请求完成后，所存储的文件并不会
    						//删除

    ngx_flag_t    client_body_in_single_buffer;	/* client_body_in_singe_buffer *///指定是否将客户端连接请求完整的放入一个
    						//缓冲区，当使用变量$request_body时推荐使用这个指令以减少复制操作。如果无
    						//法将一个请求放入单个缓冲区，将会被放入磁盘
    ngx_flag_t    internal;                /* internal *///指定location只能被"内部的"请求调用，外部的调用请求会返回"Not found"(404)
    ngx_flag_t    sendfile;                /* sendfile */	//是否启用sendfile()函数
    ngx_flag_t    aio;                     /* aio */
    ngx_flag_t    tcp_nopush;              /* tcp_nopush */
    ngx_flag_t    tcp_nodelay;             /* tcp_nodelay */
    ngx_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    ngx_flag_t    server_name_in_redirect; /* server_name_in_redirect *///指定是否在基于域名的虚拟主机中开启最优化的主机名
    						//检查。尤其是检查影响到使用主机名的重定向，如果开启最优化，那么所有基于域
    						//名的虚拟主机监听的一个“地址：端口对”具有相同的配置，这样在请求执行的时候
    						//并不进行再次检查，重定向会使用第一个server name。如果重定向必须使用主机名
    						//并且在客户端检查通过，那么这个参数必须设置为off。
    ngx_flag_t    port_in_redirect;        /* port_in_redirect */
    ngx_flag_t    msie_padding;            /* msie_padding */
    ngx_flag_t    msie_refresh;            /* msie_refresh */
    ngx_flag_t    log_not_found;           /* log_not_found */
    ngx_flag_t    log_subrequest;          /* log_subrequest */
    ngx_flag_t    recursive_error_pages;   /* recursive_error_pages */
    ngx_flag_t    server_tokens;           /* server_tokens */
    ngx_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    ngx_flag_t    etag;                    /* etag */

#if (NGX_HTTP_GZIP)
    ngx_flag_t    gzip_vary;               /* gzip_vary *///跟Squid等缓存服务有关，on的话会在Header里增加"Vary: Accept-Encoding"

    ngx_uint_t    gzip_http_version;       /* gzip_http_version *///用于设置支持GZIP的HTTP协议版本，默认是1.1
    ngx_uint_t    gzip_proxied;            /* gzip_proxied */	//Nginx作为反向代理的时候启用，根据某些请求和应答来决定是否
    						//在对代理请求的应答启用gzip压缩，是否压缩取决于请求头中的“Via”字段，指令中
    						//可以同时指定多个不同的参数，意义如下:
    						//	expired - 启用压缩，如果header头中包含 "Expires" 头信息
    						//	no-cache - 启用压缩，如果header头中包含"Cache-Control:no-cache"头信息
   						//	no-store - 启用压缩，如果header头中包含"Cache-Control:no-store"头信息
    						//	private - 启用压缩，如果header头中包含"Cache-Control:private" 头信息
    						//	no_last_modified - 启用压缩,如果header头中不包含"Last-Modified"头信息
   						//	no_etag - 启用压缩 ,如果header头中不包含"ETag"头信息
    						//	auth - 启用压缩 , 如果header头中包含 "Authorization" 头信息
    						//	any - 无条件启用压缩

#if (NGX_PCRE)
    ngx_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (NGX_THREADS)
    ngx_thread_pool_t         *thread_pool;
    ngx_http_complex_value_t  *thread_pool_value;
#endif

#if (NGX_HAVE_OPENAT)
    ngx_uint_t    disable_symlinks;        /* disable_symlinks */
    ngx_http_complex_value_t  *disable_symlinks_from;
#endif

    ngx_array_t  *error_pages;             /* error_page */
    ngx_http_try_file_t    *try_files;     /* try_files */

    ngx_path_t   *client_body_temp_path;   /* client_body_temp_path */	//指定连接请求实体试图写入的临时文件路径。可以指定三
    						//级目录结构，如：client_body_temp_path  /spool/nginx/client_temp 1 2;
    						//那么它的目录结构可能是这样：/spool/nginx/client_temp/7/45/00000123457 

    ngx_open_file_cache_t  *open_file_cache;	//指定缓存是否启用，如果启用，将记录文件以下信息：
						//	打开的文件描述符，大小信息和修改时间。
						//	存在的目录信息。
						//	在搜索文件过程中的错误信息 – 没有这个文件、无法正确读取，参考open_file_cache_errors
						//指令选项：
						//	max - 指定缓存的最大数目，如果缓存溢出，最近最少使用的文件（LRU）将被移除。
						//	inactive - 指定缓存文件被移除的时间，如果在这段时间内文件没被下载，默认为60秒。
						//	off - 禁止缓存。 

    time_t        open_file_cache_valid;	//指定了何时需要检查open_file_cache中缓存项目的有效信息
    ngx_uint_t    open_file_cache_min_uses;	//指定了在open_file_cache指令无效的参数中一定的时间范围内可以使用的最小文件
    						//数，如果使用更大的值，文件描述符在cache中总是打开状态。
    ngx_flag_t    open_file_cache_errors;
    ngx_flag_t    open_file_cache_events;	//指定是否在搜索一个文件是记录cache错误

    ngx_log_t    *error_log;			//错误日志handler

    ngx_uint_t    types_hash_max_size;
    ngx_uint_t    types_hash_bucket_size;

    ngx_queue_t  *locations;

#if 0
    ngx_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    ngx_queue_t                      queue;	//queue将作为ngx_queue_t 双向链表容器，从而将ngx_http_location_queue_t结构体
    						//连接起来

    ngx_http_core_loc_conf_t        *exact;	//如果location中的字符串可以精确匹配（包括正则），exact将指向对应的
    						//ngx_http_core_loc_conf_t结构体，否则值为null

    ngx_http_core_loc_conf_t        *inclusive;	//如果location中的字符串无法精确匹配（包括自定义的通配符），inclusive将指向
    						//对应的ngx_http_core_loc_conf_t 结构体，否则值为null

    ngx_str_t                       *name;	//指向location的名称
    u_char                          *file_name;
    ngx_uint_t                       line;
    ngx_queue_t                      list;
} ngx_http_location_queue_t;


struct ngx_http_location_tree_node_s {
    ngx_http_location_tree_node_t   *left;
    ngx_http_location_tree_node_t   *right;
    ngx_http_location_tree_node_t   *tree;

    ngx_http_core_loc_conf_t        *exact;
    ngx_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void ngx_http_core_run_phases(ngx_http_request_t *r);
ngx_int_t ngx_http_core_generic_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_find_config_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_rewrite_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_post_access_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_try_files_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);
ngx_int_t ngx_http_core_content_phase(ngx_http_request_t *r,
    ngx_http_phase_handler_t *ph);


void *ngx_http_test_content_type(ngx_http_request_t *r, ngx_hash_t *types_hash);
ngx_int_t ngx_http_set_content_type(ngx_http_request_t *r);
void ngx_http_set_exten(ngx_http_request_t *r);
ngx_int_t ngx_http_set_etag(ngx_http_request_t *r);
void ngx_http_weak_etag(ngx_http_request_t *r);
ngx_int_t ngx_http_send_response(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t *ct, ngx_http_complex_value_t *cv);
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *name,
    size_t *root_length, size_t reserved);
ngx_int_t ngx_http_auth_basic_user(ngx_http_request_t *r);
#if (NGX_HTTP_GZIP)
ngx_int_t ngx_http_gzip_ok(ngx_http_request_t *r);
#endif


ngx_int_t ngx_http_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **sr,
    ngx_http_post_subrequest_t *psr, ngx_uint_t flags);
ngx_int_t ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args);
ngx_int_t ngx_http_named_location(ngx_http_request_t *r, ngx_str_t *name);


ngx_http_cleanup_t *ngx_http_cleanup_add(ngx_http_request_t *r, size_t size);


typedef ngx_int_t (*ngx_http_output_header_filter_pt)(ngx_http_request_t *r);
typedef ngx_int_t (*ngx_http_output_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);
typedef ngx_int_t (*ngx_http_request_body_filter_pt)
    (ngx_http_request_t *r, ngx_chain_t *chain);


ngx_int_t ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *chain);
ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
   ngx_chain_t *chain);


ngx_int_t ngx_http_set_disable_symlinks(ngx_http_request_t *r,
    ngx_http_core_loc_conf_t *clcf, ngx_str_t *path, ngx_open_file_info_t *of);

ngx_int_t ngx_http_get_forwarded_addr(ngx_http_request_t *r, ngx_addr_t *addr,
    ngx_array_t *headers, ngx_str_t *value, ngx_array_t *proxies,
    int recursive);


extern ngx_module_t  ngx_http_core_module;

extern ngx_uint_t ngx_http_max_module;

extern ngx_str_t  ngx_http_core_get_method;


#define ngx_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define ngx_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define ngx_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define ngx_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define ngx_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _NGX_HTTP_CORE_H_INCLUDED_ */
