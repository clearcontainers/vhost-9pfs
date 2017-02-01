#ifndef _VHOST_9P_H
#define _VHOST_9P_H

#include "vhost.h"

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

#endif
