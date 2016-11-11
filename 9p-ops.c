/*
 * The in-kernel 9p server
 */

#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/in.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/ipv6.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/un.h>
#include <linux/uaccess.h>
#include <linux/inet.h>
#include <linux/idr.h>
#include <linux/file.h>
#include <linux/parser.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <net/9p/9p.h>

#include "vhost-9p.h"
#include "protocol.h"

const size_t P9_PDU_HDR_LEN = sizeof(u32) + sizeof(u8) + sizeof(u16);
/*
	TODO:
		- Do not use syscalls
		- Use inode_op and file_op
		- use path and dentry to replace real_path and path
		- Full support of setattr
		- chmod
		- Zero-copy
		- Should have a lock to protect fids
		- Security: parent dir reference
*/

struct p9_local_fid {
	u32 fid;
	u32 uid;
	char real_path[PATH_MAX];	// Absolute path in the file system
	char *path;					// Relative path to the base. Starts with "/"
	struct file *filp;
	struct rb_node node;
};

/* 9p helper routines */

static struct p9_local_fid *find_fid(struct vhost_9p *dev, u32 fid_val)
{
	struct rb_node *node = dev->fids.rb_node;
	struct p9_local_fid *cur;

	while (node) {
		cur = rb_entry(node, struct p9_local_fid, node);

		if (fid_val < cur->fid)
			node = node->rb_left;
		else if (fid_val > cur->fid)
			node = node->rb_right;
		else
			return cur;
	}

	return ERR_PTR(-ENOENT);
}

static struct p9_local_fid *alloc_fid(struct vhost_9p *dev, u32 fid_val,
									  const char *path)
{
	struct p9_local_fid *fid;

	fid = kmalloc(sizeof(struct p9_local_fid), GFP_KERNEL);
	if (!fid)
		return NULL;

	fid->fid = fid_val;
	fid->uid = dev->uid;
	fid->filp = NULL;

	snprintf(fid->real_path, PATH_MAX, "%s%s", dev->base, path);
	fid->path = fid->real_path + strlen(dev->base);

	return fid;
}

static struct p9_local_fid *new_fid(struct vhost_9p *dev, u32 fid_val,
									const char *path)
{
	struct p9_local_fid *fid;
	struct rb_node **node = &(dev->fids.rb_node), *parent = NULL;

	while (*node) {
		int result = fid_val - rb_entry(*node, struct p9_local_fid, node)->fid;

		parent = *node;
		if (result < 0)
			node = &((*node)->rb_left);
		else if (result > 0)
			node = &((*node)->rb_right);
		else
			return ERR_PTR(-EEXIST);
	}

	fid = alloc_fid(dev, fid_val, path);
	if (!fid)
		return ERR_PTR(-ENOMEM);

	rb_link_node(&fid->node, parent, node);
	rb_insert_color(&fid->node, &dev->fids);

	return fid;
}

static void iov_iter_clone(struct iov_iter *dst, struct iov_iter *src)
{
	memcpy(dst, src, sizeof(struct iov_iter));
}

static int lstat(const char *real_path, struct kstat *out)
{
	int err;
	mm_segment_t fs;

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = vfs_lstat(real_path, out);
	set_fs(fs);

	return err;
}

static void stat2qid(struct kstat *st, struct p9_qid *qid)
{
	*qid = (struct p9_qid) {
		.path		= st->ino,
		.version	= st->mtime.tv_sec,
	};

	if (S_ISDIR(st->mode))
		qid->type	|= P9_QTDIR;
}

static int gen_qid(const char *real_path, struct p9_qid *qid, struct kstat *st)
{
	int err;
	struct kstat _st;

	if (!st)
		st = &_st;

	err = lstat(real_path, st);
	if (err)
		return err;

	stat2qid(st, qid);
	return 0;
}

/* 9p operation functions */

static int p9_local_op_version(struct vhost_9p *dev, struct p9_fcall *in,
							   struct p9_fcall *out)
{
	u32 msize;
	char *version;

	p9pdu_readf(in, "ds", &msize, &version);

	if (!strcmp(version, "9P2000.L"))
		p9pdu_writef(out, "ds", msize, version);
	else
		p9pdu_writef(out, "ds", msize, "unknown");

	kfree(version);
	return 0;
}

static int p9_local_op_attach(struct vhost_9p *dev, struct p9_fcall *in,
							  struct p9_fcall *out)
{
	int err;
	char *uname, *aname;
	struct p9_qid qid;
	struct p9_local_fid *fid;
	u32 fid_val, afid, uid;

	p9pdu_readf(in, "ddssd", &fid_val, &afid,
				&uname, &aname, &uid);
	kfree(uname);
	kfree(aname);

	dev->uid = uid;
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid)) {
		fid = new_fid(dev, fid_val, "");
		if (IS_ERR(fid))
			return PTR_ERR(fid);
	}

	err = gen_qid(fid->real_path, &qid, NULL);
	if (err)
		return err;

	p9pdu_writef(out, "Q", &qid);
	return 0;
}

static int p9_local_op_getattr(struct vhost_9p *dev, struct p9_fcall *in,
								struct p9_fcall *out)
{
	int err;
	u32 fid_val;
	u64 request_mask;
	struct p9_local_fid *fid;
	struct kstat st;
	struct p9_qid qid;

	p9pdu_readf(in, "dq", &fid_val, &request_mask);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	err = gen_qid(fid->real_path, &qid, &st);
	if (err)
		return err;

	p9pdu_writef(out, "qQdugqqqqqqqqqqqqqqq",
		P9_STATS_BASIC, &qid, st.mode, st.uid, st.gid,
		st.nlink, st.rdev, st.size, st.blksize, st.blocks,
		st.atime.tv_sec, st.atime.tv_nsec,
		st.mtime.tv_sec, st.mtime.tv_nsec,
		st.ctime.tv_sec, st.ctime.tv_nsec,
		0, 0, 0, 0);

	return 0;
}

static int p9_local_op_clunk(struct vhost_9p *dev, struct p9_fcall *in,
							 struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_local_fid *fid;

	p9pdu_readf(in, "d", &fid_val);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (!IS_ERR_OR_NULL(fid->filp))
		filp_close(fid->filp, NULL);

	rb_erase(&fid->node, &dev->fids);
	kfree(fid);

	return 0;
}

static int p9_local_op_walk(struct vhost_9p *dev, struct p9_fcall *in,
							struct p9_fcall *out)
{
	int err;
	size_t t;
	u16 nwqid, nwname;
	u32 fid_val, newfid_val;
	struct p9_qid qid;
	struct p9_local_fid *fid, *newfid;
	char *name, *tail;

	p9pdu_readf(in, "ddw", &fid_val, &newfid_val, &nwname);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (fid_val == newfid_val) {
		/* Fake an fid for path storage */
		newfid = alloc_fid(dev, newfid_val, fid->path);
	} else {
		newfid = new_fid(dev, newfid_val, fid->path);
		if (IS_ERR(newfid))
			return PTR_ERR(newfid);
	}

	t = strlen(newfid->real_path);
	tail = newfid->real_path + t;
	t = PATH_MAX - t;

	out->size += sizeof(u16);

	for (nwqid = 0; nwqid < nwname; nwqid++) {
		p9pdu_readf(in, "s", &name);
		snprintf(tail, t, "/%s", name);
		kfree(name);

		err = gen_qid(newfid->real_path, &qid, NULL);
		if (err)
			break;

		p9pdu_writef(out, "Q", &qid);
	}

	if (fid_val == newfid_val)
		kfree(newfid);

	t = out->size;
	out->size = P9_PDU_HDR_LEN;
	p9pdu_writef(out, "w", nwqid);
	out->size = t;

	return 0;
}

static int p9_local_op_statfs(struct vhost_9p *dev, struct p9_fcall *in,
							  struct p9_fcall *out)
{
	int err;
	u64 fsid;
	u32 fid_val;
	struct p9_local_fid *fid;
	struct statfs st;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_statfs(fid->real_path, &st);
	set_fs(fs);

	if (err)
		return err;

	/* FIXME!! f_blocks needs update based on client msize */
	fsid = (unsigned int) st.f_fsid.val[0] |
		(unsigned long long)st.f_fsid.val[1] << 32;

	p9pdu_writef(out, "ddqqqqqqd", st.f_type,
			     st.f_bsize, st.f_blocks, st.f_bfree, st.f_bavail,
			     st.f_files, st.f_ffree, fsid, st.f_namelen);

	return 0;
}

/*
 * FIXME!! Need to map to protocol independent value. Upstream
 * 9p also have the same BUG
 */
static int p9_local_openflags(int flags)
{
	flags &= ~(O_NOCTTY | FASYNC | O_CREAT | O_DIRECT);
	flags |= O_NOFOLLOW;
	return flags;
}

static int p9_local_op_open(struct vhost_9p *dev, struct p9_fcall *in,
							struct p9_fcall *out)
{
	int err;
	u32 fid_val, flags;
	struct p9_qid qid;
	struct p9_local_fid *fid;

	p9pdu_readf(in, "dd", &fid_val, &flags);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	err = gen_qid(fid->real_path, &qid, NULL);
	if (err)
		return err;

	fid->filp = filp_open(fid->real_path, p9_local_openflags(flags), 0);
	if (IS_ERR(fid->filp))
		return PTR_ERR(fid->filp);

	/* FIXME!! need ot send proper iounit  */
	p9pdu_writef(out, "Qd", &qid, 0L);

	return 0;
}

static int p9_local_op_create(struct vhost_9p *dev, struct p9_fcall *in,
							  struct p9_fcall *out)
{
	int err;
	char *name;
	struct p9_qid qid;
	struct p9_local_fid *fid;
	u32 fid_val, flags, mode, gid;

	p9pdu_readf(in, "d", &fid_val);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "sddd", &name, &flags, &mode, &gid);
	snprintf(fid->real_path, PATH_MAX, "%s/%s", fid->real_path, name);
	kfree(name);

	fid->filp = filp_open(fid->real_path, p9_local_openflags(flags) | O_CREAT, mode);
	if (IS_ERR(fid->filp))
		return PTR_ERR(fid->filp);

/*	err = chmod(fid->real_path, mode & 0777);
	if (err < 0)
		return err;
*/
	err = gen_qid(fid->real_path, &qid, NULL);
	if (err)
		return err;

	p9pdu_writef(out, "Qd", &qid, 0L);

	return 0;
}

struct p9_local_dirent {
	u64 d_off;
	u8 d_type;
	const char *d_name;
};

struct readdir_callback {
	struct dir_context ctx;
	size_t i, n;
	struct p9_local_dirent *out;
};

/* Callback function from iterate_dir */

static int fill_dirent(struct dir_context *ctx, const char *name, int namlen,
		   loff_t offset, u64 ino, unsigned int d_type)
{
	struct p9_local_dirent *dirent;
	struct readdir_callback *buf = container_of(ctx, struct readdir_callback, ctx);

	if (buf->i >= buf->n)
		return EINVAL;

	dirent = &buf->out[buf->i++];
	dirent->d_off = offset;	// BUG: offset should be put to the previous dirent
	dirent->d_name = name;
	dirent->d_type = d_type;

	return 0;
}

static int p9_local_op_readdir(struct vhost_9p *dev, struct p9_fcall *in,
							   struct p9_fcall *out)
{
	int err;
	u32 fid_val, count;
	u64 offset;
	struct p9_qid qid;
	struct p9_local_fid *fid;
	struct p9_local_dirent *dent;
	char *path, *tail;
	size_t i, t;
	struct readdir_callback buf = {
		.ctx.actor = fill_dirent,
		.i = 0,
	};

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);

	/* TODO: meaning of offset unknown */
//	printk("GUOYK: offset: %lld\n", offset);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

//	buf.ctx.pos = offset;
	buf.n = count / sizeof(struct p9_local_dirent);
	buf.out = kmalloc(count, GFP_KERNEL);

	err = iterate_dir(fid->filp, &buf.ctx);
	if (err)
		return err;

	out->size += sizeof(u32);	// Skip the space for writing count

	path = kmalloc(PATH_MAX, GFP_KERNEL);
	strcpy(path, fid->real_path);
	t = strlen(path);
	tail = path + t;
	t = PATH_MAX - t;

	for (i = 0; i < buf.i; i++) {
		dent = &buf.out[i];
		snprintf(tail, t, "/%s", dent->d_name);

		err = gen_qid(path, &qid, NULL);
		if (err)
			return err;

		p9pdu_writef(out, "Qqbs", &qid, dent->d_off,
					 dent->d_type, dent->d_name);
	}

	kfree(path);
	kfree(buf.out);

	t = out->size - P9_PDU_HDR_LEN - sizeof(u32);
	out->size = P9_PDU_HDR_LEN;
	p9pdu_writef(out, "d", (u32) t);
	out->size += t;

	return 0;
}

static int p9_local_op_read(struct vhost_9p *dev, struct p9_fcall *in,
							struct p9_fcall *out)
{
	u32 fid_val, count;
	u64 offset;
	ssize_t len;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	out->size += sizeof(u32);

	if (count + out->size > out->capacity)
		count = out->capacity - out->size;

	fs = get_fs();
	set_fs(KERNEL_DS);
	len = vfs_read(fid->filp, out->sdata + out->size, count, &offset);
	set_fs(fs);

	if (len < 0)
		return len;

	out->size = P9_PDU_HDR_LEN;
	p9pdu_writef(out, "d", (u32) len);
	out->size += len;

	return 0;
}

static int p9_local_op_readv(struct vhost_9p *dev, struct p9_fcall *in,
							struct p9_fcall *out, struct iov_iter *data)
{
	u32 fid_val, count;
	u64 offset;
	ssize_t len;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (data->count > count)
		data->count = count;

	fs = get_fs();
	set_fs(KERNEL_DS);
	len = vfs_iter_read(fid->filp, data, &offset);
	set_fs(fs);

	if (len < 0)
		return len;

	p9pdu_writef(out, "d", (u32) len);
	out->size += len;

	return 0;
}

#define ATTR_MASK	127

static int p9_local_op_setattr(struct vhost_9p *dev, struct p9_fcall *in,
							   struct p9_fcall *out)
{
	int err = 0; /* TODO: remove */
	u32 fid_val;
	struct p9_local_fid *fid;
	struct p9_iattr_dotl p9attr;
	mm_segment_t fs;

	p9pdu_readf(in, "dddugqqqqq", &fid_val, 
				&p9attr.valid, &p9attr.mode,
				&p9attr.uid, &p9attr.gid, &p9attr.size,
				&p9attr.atime_sec, &p9attr.atime_nsec,
				&p9attr.mtime_sec, &p9attr.mtime_nsec);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);
/*
	if (p9attr.valid & ATTR_MODE) {
		err = chmod(fid->real_path, p9attr.mode);
		if (err < 0)
			return err;
	}

	if (p9attr.valid & (ATTR_ATIME | ATTR_MTIME)) {
		struct timespec times[2];

		if (p9attr.valid & ATTR_ATIME) {
			if (p9attr.valid & ATTR_ATIME_SET) {
				times[0].tv_sec = p9attr.atime_sec;
				times[0].tv_nsec = p9attr.atime_nsec;
			} else
				times[0].tv_nsec = UTIME_NOW;
		} else
			times[0].tv_nsec = UTIME_OMIT;

		if (p9attr.valid & ATTR_MTIME) {
			if (p9attr.valid & ATTR_MTIME_SET) {
				times[1].tv_sec = p9attr.mtime_sec;
				times[1].tv_nsec = p9attr.mtime_nsec;
			} else
				times[1].tv_nsec = UTIME_NOW;
		} else
			times[1].tv_nsec = UTIME_OMIT;

		err = utimensat(-1, fid->real_path, times, AT_SYMLINK_NOFOLLOW);
		if (err < 0)
			return err;
	}
*/	/*
	 * If the only valid entry in iattr is ctime we can call
	 * chown(-1,-1) to update the ctime of the file
	 */
/*	if ((p9attr.valid & (ATTR_UID | ATTR_GID)) ||
	    ((p9attr.valid & ATTR_CTIME)
	     && !((p9attr.valid & ATTR_MASK) & ~ATTR_CTIME))) {
		if (!(p9attr.valid & ATTR_UID))
			p9attr.uid = KUIDT_INIT(-1);

		if (!(p9attr.valid & ATTR_GID))
			p9attr.gid = KGIDT_INIT(-1);

		err = lchown(fid->real_path, __kuid_val(p9attr.uid),
				__kgid_val(p9attr.gid));
		if (err < 0)
			return err;
	}
*/
	if (p9attr.valid & ATTR_SIZE) {
		fs = get_fs();
		set_fs(KERNEL_DS);
		err = sys_truncate(fid->real_path, p9attr.size);
		set_fs(fs);

		if (err < 0)
			return err;
	}

	return 0;
}

static int p9_local_op_write(struct vhost_9p *dev, struct p9_fcall *in,
							 struct p9_fcall *out)
{
	u64 offset;
	u32 fid_val, count;
	ssize_t len;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	fs = get_fs();
	set_fs(KERNEL_DS);
	len = vfs_write(fid->filp, in->sdata + in->offset, count, &offset);
	set_fs(fs);

	if (len < 0)
		return len;

	p9pdu_writef(out, "d", (u32) len);
	return 0;
}

static int p9_local_op_writev(struct vhost_9p *dev, struct p9_fcall *in,
							 struct p9_fcall *out, struct iov_iter *data)
{
	u64 offset;
	u32 fid_val, count;
	ssize_t len;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (data->count > count)
		data->count = count;

	fs = get_fs();
	set_fs(KERNEL_DS);
	len = vfs_iter_write(fid->filp, data, &offset);
	set_fs(fs);

	if (len < 0)
		return len;

	p9pdu_writef(out, "d", (u32) len);
	return 0;
}

static int p9_local_op_remove(struct vhost_9p *dev, struct p9_fcall *in,
							  struct p9_fcall *out)
{
	int err;
	u32 fid_val;
	struct kstat st;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	err = lstat(fid->real_path, &st);
	if (err < 0)
		return err;

	fs = get_fs();
	set_fs(KERNEL_DS);

	if (S_ISDIR(st.mode))
		err = sys_rmdir(fid->real_path);
	else
		err = sys_unlink(fid->real_path);

	set_fs(fs);

	return err;
}

static int p9_local_op_rename(struct vhost_9p *dev, struct p9_fcall *in,
							  struct p9_fcall *out)
{
	int err;
	u32 fid_val, newfid_val;
	char *path;
	struct p9_local_fid *fid, *newfid;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "ds", &newfid_val, &path);
	newfid = new_fid(dev, newfid_val, path);
	kfree(path);
	if (IS_ERR(newfid))
		return PTR_ERR(newfid);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_rename(fid->real_path, newfid->real_path);
	set_fs(fs);

	return err;
}

static int p9_local_op_mkdir(struct vhost_9p *dev, struct p9_fcall *in,
							 struct p9_fcall *out)
{
	int err;
	u32 fid_val, mode, gid;
	char *name, *path;
	struct p9_qid qid;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "sdd", &name, &mode, &gid);
	path = kmalloc(PATH_MAX, GFP_KERNEL);
	snprintf(path, PATH_MAX, "%s/%s", fid->real_path, name);
	kfree(name);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_mkdir(path, mode);
	set_fs(fs);

	if (err < 0)
		goto out;
/*
	err = chmod(path, mode & 0777);
	if (err < 0)
		goto out;
*/
	err = gen_qid(path, &qid, NULL);
	if (err)
		goto out;

	p9pdu_writef(out, "Qd", &qid, 0L);

out:
	kfree(path);
	return err;
}

static int p9_local_op_symlink(struct vhost_9p *dev, struct p9_fcall *in,
							   struct p9_fcall *out)
{
	int err;
	u32 fid_val, gid;
	struct p9_qid qid;
	struct p9_local_fid *fid;
	char *name, *src, *symlink_path;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "ssd", &name, &src, &gid);
	symlink_path = kmalloc(PATH_MAX, GFP_KERNEL);
	snprintf(symlink_path, PATH_MAX, "%s/%s", fid->real_path, name);
	kfree(name);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_symlink(src, symlink_path);
	set_fs(fs);
	kfree(src);

	if (err < 0)
		goto out;

	err = gen_qid(symlink_path, &qid, NULL);
	if (err)
		goto out;

	p9pdu_writef(out, "Q", &qid);
out:
	kfree(symlink_path);
	return err;
}

static int p9_local_op_link(struct vhost_9p *dev, struct p9_fcall *in,
							struct p9_fcall *out)
{
	int err;
	u32 fid_val, dfid_val;
	char *path, *name;
	struct p9_local_fid *dfid, *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dd", &dfid_val, &fid_val);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	dfid = find_fid(dev, dfid_val);
	if (IS_ERR(dfid))
		return PTR_ERR(dfid);

	p9pdu_readf(in, "s", &name);
	path = kmalloc(PATH_MAX, GFP_KERNEL);
	snprintf(path, PATH_MAX, "%s/%s", dfid->real_path, name);
	kfree(name);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_link(fid->real_path, path);
	set_fs(fs);

	kfree(path);
	return err;
}

static int p9_local_op_readlink(struct vhost_9p *dev, struct p9_fcall *in,
								struct p9_fcall *out)
{
	int err;
	u32 fid_val;
	char *path;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	path = kmalloc(PATH_MAX, GFP_KERNEL);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_readlink(fid->real_path, path, PATH_MAX);
	set_fs(fs);

	if (err < 0)
		return err;

	p9pdu_writef(out, "s", path);
	kfree(path);
	return 0;
}

static int p9_local_op_fsync(struct vhost_9p *dev, struct p9_fcall *in,
							 struct p9_fcall *out)
{
	int err = 0;
	u32 fid_val, datasync;
	struct p9_local_fid *fid;

	p9pdu_readf(in, "dd", &fid_val, &datasync);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (!IS_ERR_OR_NULL(fid->filp))
		err = vfs_fsync(fid->filp, datasync);

	return err;
}

static int p9_local_op_mknod(struct vhost_9p *dev, struct p9_fcall *in,
							 struct p9_fcall *out)
{
	int err;
	u32 fid_val, mode, major, minor, gid;
	char *name, *path;
	struct p9_qid qid;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "sdddd", &name, &mode, &major, &minor, &gid);
	path = kmalloc(PATH_MAX, GFP_KERNEL);
	snprintf(path, PATH_MAX, "%s/%s", fid->real_path, name);
	kfree(name);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_mknod(path, mode, MKDEV(major, minor));
	set_fs(fs);

	if (err < 0)
		goto out;
/*
	err = chmod(path, mode & 0777);
	if (err < 0)
		goto out;
*/
	err = gen_qid(path, &qid, NULL);
	if (err)
		goto out;

	p9pdu_writef(out, "Q", &qid);
out:
	kfree(path);
	return err;
}

static int p9_local_op_lock(struct vhost_9p *dev, struct p9_fcall *in,
							struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_flock flock;

	p9pdu_readf(in, "dbdqqds", &fid_val, &flock.type,
			    &flock.flags, &flock.start, &flock.length,
			    &flock.proc_id, &flock.client_id);

	kfree(flock.client_id);

	/* Just return success */
	p9pdu_writef(out, "d", (u8) P9_LOCK_SUCCESS);
	return 0;
}

static int p9_local_op_getlock(struct vhost_9p *dev, struct p9_fcall *in,
							   struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_getlock glock;

	p9pdu_readf(in, "dbqqds", &fid_val, &glock.type,
				&glock.start, &glock.length, &glock.proc_id,
				&glock.client_id);

	/* Just return success */
	glock.type = F_UNLCK;
	p9pdu_writef(out, "bqqds", glock.type,
				 glock.start, glock.length, glock.proc_id,
				 glock.client_id);

	kfree(glock.client_id);
	return 0;
}

static int p9_local_op_unlinkat(struct vhost_9p *dev, struct p9_fcall *in,
								struct p9_fcall *out)
{
	int err;
	u32 fid_val, flags;
	char *name, *path;
	struct p9_local_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "d", &fid_val);
	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "sd", &name, &flags);
	path = kmalloc(PATH_MAX, GFP_KERNEL);
	snprintf(path, PATH_MAX, "%s/%s", fid->real_path, name);
	kfree(name);

	fs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_unlinkat(AT_FDCWD, path, flags);
	set_fs(fs);

	kfree(path);
	return err;
}

static void rename_fids(struct vhost_9p *dev, char *old_path, char *new_path)
{
	struct rb_node *node;
	struct p9_local_fid *fid;
	size_t len;
	char *t;

	t = kmalloc(PATH_MAX, GFP_KERNEL);
	len = strlen(old_path);

	for (node = rb_first(&dev->fids); node; node = rb_next(node)) {
		fid = rb_entry(node, struct p9_local_fid, node);

		if (fid->fid == P9_NOFID)
			continue;

		if (strncmp(fid->real_path, old_path, len) == 0 &&
			(fid->real_path[len] == '/' || fid->real_path[len] == '\0')) {
			strncpy(t, fid->real_path + len, PATH_MAX);
			snprintf(fid->real_path, PATH_MAX, "%s/%s", new_path, t);
		}
	}

	kfree(t);
}

static int p9_local_op_renameat(struct vhost_9p *dev, struct p9_fcall *in,
								struct p9_fcall *out)
{
	int err;
	u32 fid_val, newfid_val;
	char *old_name, *new_name, *old_path, *new_path;
	struct p9_local_fid *fid, *newfid;

	p9pdu_readf(in, "dsds", &fid_val, &old_name,
			    &newfid_val, &new_name);

	fid = find_fid(dev, fid_val);
	if (IS_ERR(fid)) {
		err = PTR_ERR(fid);
		goto out1;
	}

	newfid = find_fid(dev, newfid_val);
	if (IS_ERR(newfid)) {
		err = PTR_ERR(newfid);
		goto out1;
	}

	old_path = kmalloc(PATH_MAX, GFP_KERNEL);
	new_path = kmalloc(PATH_MAX, GFP_KERNEL);
	snprintf(old_path, PATH_MAX, "%s/%s", fid->real_path, old_name);
	snprintf(new_path, PATH_MAX, "%s/%s", newfid->real_path, new_name);

	err = sys_renameat(AT_FDCWD, old_path, AT_FDCWD, new_path);
	if (err < 0)
		goto out2;

	/* Now fix path in other fids, if the renamed path is part of that. */
	rename_fids(dev, old_path, new_path);

out2:
	kfree(old_path);
	kfree(new_path);
out1:
	kfree(old_name);
	kfree(new_name);
	return err;
}

static int p9_local_op_flush(struct vhost_9p *dev, struct p9_fcall *in,
							 struct p9_fcall *out)
{
	u16 tag, oldtag;

	p9pdu_readf(in, "ww", &tag, &oldtag);
	p9pdu_writef(out, "w", tag);

	return 0;
}

typedef int p9_local_op(struct vhost_9p *dev, struct p9_fcall *in,
			struct p9_fcall *out);

static p9_local_op *p9_local_ops [] = {
//	[P9_TLERROR]      = p9_local_op_error,	// Not used
	[P9_TSTATFS]      = p9_local_op_statfs,
	[P9_TLOPEN]       = p9_local_op_open,
	[P9_TLCREATE]     = p9_local_op_create,
	[P9_TSYMLINK]     = p9_local_op_symlink,
	[P9_TMKNOD]       = p9_local_op_mknod,
	[P9_TRENAME]      = p9_local_op_rename,
	[P9_TREADLINK]    = p9_local_op_readlink,
	[P9_TGETATTR]     = p9_local_op_getattr,
	[P9_TSETATTR]     = p9_local_op_setattr,
//	[P9_TXATTRWALK]   = p9_local_op_xattrwalk,	// Not implemented
//	[P9_TXATTRCREATE] = p9_local_op_xattrcreate,	// Not implemented
	[P9_TREADDIR]     = p9_local_op_readdir,
	[P9_TFSYNC]       = p9_local_op_fsync,
	[P9_TLOCK]        = p9_local_op_lock,
	[P9_TGETLOCK]     = p9_local_op_getlock,
	[P9_TLINK]        = p9_local_op_link,
	[P9_TMKDIR]       = p9_local_op_mkdir,
	[P9_TRENAMEAT]    = p9_local_op_renameat,
	[P9_TUNLINKAT]    = p9_local_op_unlinkat,
	[P9_TVERSION]     = p9_local_op_version,
//	[P9_TAUTH]        = p9_local_op_auth,	// Not implemented
	[P9_TATTACH]      = p9_local_op_attach,
//	[P9_TERROR]       = p9_local_op_error,		// Not used
	[P9_TFLUSH]       = p9_local_op_flush,
	[P9_TWALK]        = p9_local_op_walk,
//	[P9_TOPEN]        = p9_local_op_open,	// Not supported in 9P2000.L
//	[P9_TCREATE]      = p9_local_op_create,	// Not supported in 9P2000.L
	[P9_TREAD]        = p9_local_op_read,
	[P9_TWRITE]       = p9_local_op_write,
	[P9_TCLUNK]       = p9_local_op_clunk,
	[P9_TREMOVE]      = p9_local_op_remove,
//	[P9_TSTAT]        = p9_local_op_stat,	// Not implemented
//	[P9_TWSTAT]       = p9_local_op_wstat,	// Not implemented
};

static const char *translate [] = {
	[P9_TLERROR]      = "error",
	[P9_TSTATFS]      = "statfs",
	[P9_TLOPEN]       = "open",
	[P9_TLCREATE]     = "create",
	[P9_TSYMLINK]     = "symlink",
	[P9_TMKNOD]       = "mknod",
	[P9_TRENAME]      = "rename",
	[P9_TREADLINK]    = "readlink",
	[P9_TGETATTR]     = "getattr",
	[P9_TSETATTR]     = "setattr",
	[P9_TXATTRWALK]   = "xattrwalk",
	[P9_TXATTRCREATE] = "xattrcreate",
	[P9_TREADDIR]     = "readdir",
	[P9_TFSYNC]       = "fsync",
	[P9_TLOCK]        = "lock",
	[P9_TGETLOCK]     = "getlock",
	[P9_TLINK]        = "link",
	[P9_TMKDIR]       = "mkdir",
	[P9_TRENAMEAT]    = "renameat",
	[P9_TUNLINKAT]    = "unlinkat",
	[P9_TVERSION]     = "version",
	[P9_TAUTH]        = "auth",
	[P9_TATTACH]      = "attach",
	[P9_TERROR]       = "error",
	[P9_TFLUSH]       = "flush",
	[P9_TWALK]        = "walk",
	[P9_TOPEN]        = "open",
	[P9_TCREATE]      = "create",
	[P9_TREAD]        = "read",
	[P9_TWRITE]       = "write",
	[P9_TCLUNK]       = "clunk",
	[P9_TREMOVE]      = "remove",
	[P9_TSTAT]        = "stat",
	[P9_TWSTAT]       = "wstat",
};

struct p9_header {
	uint32_t size;
	uint8_t id;
	uint16_t tag;
} __attribute__((packed));

struct p9_io_header {
	uint32_t size;
	uint8_t id;
	uint16_t tag;
	uint32_t fid;
	uint64_t offset;
	uint32_t count;
} __attribute__((packed));

static struct p9_fcall *new_pdu(size_t size)
{
	struct p9_fcall *pdu;

	pdu = kmalloc(sizeof(struct p9_fcall) + size, GFP_KERNEL);
	pdu->size = 0;	// write offset
	pdu->offset = 0;	// read offset
	pdu->capacity = size;
	pdu->sdata = (void *)pdu + sizeof(struct p9_fcall);	// Make the data area right after the pdu structure

	return pdu;
}

static size_t pdu_fill(struct p9_fcall *pdu, struct iov_iter *from, size_t size)
{
	size_t ret, len;

	len = min(pdu->capacity - pdu->size, size);
	ret = copy_from_iter(&pdu->sdata[pdu->size], len, from);

	pdu->size += ret;
	return size - ret;
}

/*
Quirks for performance optimization
1. copy size is io_header

 */

void do_9p_request(struct vhost_9p *dev, struct iov_iter *req, struct iov_iter *resp)
{
	int err = -EOPNOTSUPP;
	u8 cmd;
	struct iov_iter data;
	struct p9_fcall *in, *out;
	struct p9_header *hdr;
	struct p9_io_header *io_hdr;

	in = new_pdu(req->count);
	out = new_pdu(resp->count);

	pdu_fill(in, req, sizeof(struct p9_io_header));
	hdr = (struct p9_header *)in->sdata;

	in->offset = out->size = sizeof(struct p9_header);
	in->tag = out->tag = hdr->tag;
	in->id = cmd = hdr->id;
	out->id = hdr->id + 1;

//	printk("GUOYK: do_9p_request: %s! %d\n", translate[cmd], in->tag);

	if (cmd < ARRAY_SIZE(p9_local_ops) && p9_local_ops[cmd]) {
		if (cmd == P9_TREAD || cmd == P9_TWRITE) {
			io_hdr = (struct p9_io_header *) hdr;

			/* Do zero-copy for large IO */
			if (io_hdr->count > 1024) {
				if (cmd == P9_TREAD) {
					iov_iter_clone(&data, resp);
					iov_iter_advance(&data, sizeof(struct p9_header) + sizeof(u32));
					resp->count = sizeof(struct p9_header) + sizeof(u32);	// Hack

					err = p9_local_op_readv(dev, in, out, &data);
				} else
					err = p9_local_op_writev(dev, in, out, req);
			} else {
				if (cmd == P9_TWRITE) {
					pdu_fill(in, req, io_hdr->count);
					err = p9_local_op_write(dev, in, out);
				} else
					err = p9_local_op_read(dev, in, out);
			}
		} else {
			/* Copy the rest data */
			if (hdr->size > sizeof(struct p9_io_header))
				pdu_fill(in, req, hdr->size - sizeof(struct p9_io_header));

			err = p9_local_ops[cmd](dev, in, out);
		}

		kfree(in);
	} else {
		if (cmd < ARRAY_SIZE(p9_local_ops))
			printk("GUOYK: !!!not implemented: %s\n", translate[cmd]);
		else
			printk("GUOYK: !!!cmd too large: %d\n", (u32) cmd);
	}

	if (err) {
		/* Compose an error reply */
		out->size = 0;
		p9pdu_writef(out, "dbwd", 
			sizeof(struct p9_header) + sizeof(u32), 
			P9_RLERROR, out->tag, (u32) -err);
	} else {
		size_t t = out->size;
		out->size = 0;
		p9pdu_writef(out, "dbw", t, out->id, out->tag);
		out->size = t;
	}

	copy_to_iter(out->sdata, out->size, resp);
	kfree(out);
}

int p9_ops_init(struct vhost_9p *dev, const char *root_dir)
{
	int err;
	struct kstat st;
	size_t len;

	printk("GUOYK: 9p local create! %s\n", root_dir);

	if (root_dir[0] != '/')
		return -EINVAL;

	len = strlen(root_dir);
	if (len > PATH_MAX - 1)
		return -ENAMETOOLONG;

	/* Check if base is dir */
	err = lstat(root_dir, &st);
	if (err)
		return err;

	if (!S_ISDIR(st.mode))
		return -ENOTDIR;

	strncpy(dev->base, root_dir, len);
	if (dev->base[len - 1] == '/')
		dev->base[len - 1] = '\0';

	dev->fids = RB_ROOT;

	return 0;
}
