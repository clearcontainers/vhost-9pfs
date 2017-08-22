#ifndef _VHOST_9P_H
#define _VHOST_9P_H

#include "vhost.h"

//#define DEBUG 1
#ifdef DEBUG
#define p9s_debug(fmt, ...)           \
    pr_info(fmt, ##__VA_ARGS__)
#else
#define p9s_debug(fmt, ...)           \
    no_printk(fmt, ##__VA_ARGS__)
#endif

struct p9_server {
	u32 uid;
	struct path root;
	struct rb_root fids;
};

enum {
	VHOST_9P_VQ = 0,
	VHOST_9P_VQ_MAX = 1,
};

struct vhost_9p {
	struct vhost_dev dev;
	struct vhost_virtqueue vqs[VHOST_9P_VQ_MAX];
	struct p9_server *server;
};

struct p9_server *p9_server_create(struct path *root);
void p9_server_close(struct p9_server *s);
void do_9p_request(struct p9_server *s, struct iov_iter *req, struct iov_iter *resp);

enum {
	P9_FID_NONE = 0,
	P9_FID_FILE,
	P9_FID_DIR,
	P9_FID_XATTR,
};

typedef struct p9_xattr_field {
	uint64_t copied_len;
	uint64_t len;
	char *value;
	char *name;
	int flags;
	bool xattrwalk_fid;
} p9_xattr_field;

struct p9_server_fid {
	u32 fid;
	u32 uid;
	struct path path;
	struct file *filp;
	struct rb_node node;
	int fid_type;
	int ref;
	int clunked;
	p9_xattr_field xattr;
};

#endif
