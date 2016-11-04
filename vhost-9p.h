#ifndef _VHOST_9P_H
#define _VHOST_9P_H

#include "vhost.h"

enum {
	VHOST_9P_VQ = 0,
	VHOST_9P_VQ_MAX = 1,
};

struct vhost_9p {
	struct vhost_dev dev;
	struct vhost_virtqueue vqs[VHOST_9P_VQ_MAX];

	u32 uid;
	char base[PATH_MAX];
	struct rb_root fids;
};

int p9_ops_init(struct vhost_9p *m, const char *root_dir);
void do_9p_request(struct vhost_9p *m, struct p9_fcall *req, struct p9_fcall *resp);

#endif
