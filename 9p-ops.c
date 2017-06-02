/*
 *	The in-kernel 9p server
 *
 *	Copyright (C) 2016 by Yuankai Guo <yuankai.guo@intel.com>
 *	Copyright (C) 2017 by Anthony Xu <anthony.xu@intel.com>
 *	Copyright (C) 2017 by Yu-chu Yang <yu-chu.yang@intel.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2
 *	as published by the Free Software Foundation.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 */

#include <linux/fs.h>
#include <linux/xattr.h>
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

#define MAX_FILE_NAME (NAME_MAX + 1)
const size_t P9_PDU_HDR_LEN = sizeof(u32) + sizeof(u8) + sizeof(u16);

struct p9_server_fid {
	u32 fid;
	u32 uid;
	struct path path;
	struct file *filp;
	struct rb_node node;
};

/* 9p helper routines */

static struct p9_server_fid *lookup_fid(struct p9_server *s, u32 fid_val)
{
	struct rb_node *node = s->fids.rb_node;
	struct p9_server_fid *cur;

	p9s_debug("find fid : %d\n", fid_val);
	while (node) {
		cur = rb_entry(node, struct p9_server_fid, node);

		if (fid_val < cur->fid)
			node = node->rb_left;
		else if (fid_val > cur->fid)
			node = node->rb_right;
		else{
			p9s_debug("fid : %d is found\n", cur->fid);
			return cur;
		}
	}

	return ERR_PTR(-ENOENT);
}

static struct p9_server_fid *new_fid(struct p9_server *s, u32 fid_val,
						struct path *path)
{
	struct p9_server_fid *fid;
	struct rb_node **node = &(s->fids.rb_node), *parent = NULL;

	p9s_debug("create fid : %d\n", fid_val);
	while (*node) {
		int result = fid_val
			- rb_entry(*node, struct p9_server_fid, node)->fid;

		parent = *node;
		if (result < 0)
			node = &((*node)->rb_left);
		else if (result > 0)
			node = &((*node)->rb_right);
		else
			return ERR_PTR(-EEXIST);
	}

	fid = kmalloc(sizeof(struct p9_server_fid), GFP_KERNEL);
	if (!fid)
		return ERR_PTR(-ENOMEM);
	fid->fid = fid_val;
	fid->uid = s->uid;
	fid->filp = NULL;
	fid->path = *path;

	rb_link_node(&fid->node, parent, node);
	rb_insert_color(&fid->node, &s->fids);
	p9s_debug("fid : %d created\n", fid_val);

	return fid;
}

static inline void iov_iter_clone(struct iov_iter *dst, struct iov_iter *src)
{
	memcpy(dst, src, sizeof(struct iov_iter));
}


static int gen_qid(struct path *path, struct p9_qid *qid, struct kstat *st)
{
	int err;
	struct kstat _st;

	if (!st)
		st = &_st;

	err = vfs_getattr(path, st);
	if (err)
		return err;

	/* TODO: incomplete types */
	qid->version = st->mtime.tv_sec;
	qid->path = st->ino;
	qid->type = P9_QTFILE;

	if (S_ISDIR(st->mode))
		qid->type |= P9_QTDIR;

	if (S_ISLNK(st->mode))
		qid->type |= P9_QTSYMLINK;

	return 0;
}

static int set_owner(struct dentry *d, int uid, int gid)
{
	int err = 0;
	struct iattr iattr;

	p9s_debug("set_owner : uid %d, gid %d\n", uid, gid);

	memset(&iattr, 0, sizeof(struct iattr));

	if (uid >= 0) {
		iattr.ia_valid |= ATTR_UID;
		iattr.ia_uid.val = uid;
	}
	if (gid >= 0) {
		iattr.ia_valid |= ATTR_GID;
		iattr.ia_gid.val = gid;
	}
	if (iattr.ia_valid) {
		inode_lock(d->d_inode);
		err = notify_change(d, &iattr, NULL);
		inode_unlock(d->d_inode);
		if (err < 0)
			return err;
	}
	return 0;
}
/* 9p operation functions */

static int p9_op_version(struct p9_server *s, struct p9_fcall *in,
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
// TODO: uname, aname, uid, afid
static int p9_op_attach(struct p9_server *s, struct p9_fcall *in,
						struct p9_fcall *out)
{
	int err;
	char *uname, *aname;
	struct p9_qid qid;
	struct p9_server_fid *fid;
	u32 fid_val, afid, uid;

	p9pdu_readf(in, "ddssd", &fid_val, &afid,
				&uname, &aname, &uid);
	p9s_debug("attach : afid %d uname %s aname %s uid %d\n",
				afid ? afid : -1, uname, aname, uid);
	kfree(uname);
	kfree(aname);

	s->uid = uid;
	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid)) {
		fid = new_fid(s, fid_val, &s->root);
		if (IS_ERR(fid))
			return PTR_ERR(fid);
	}

	err = gen_qid(&fid->path, &qid, NULL);
	if (err)
		return err;

	p9s_debug("attached : qid = %x.%llx.%x\n",
			qid.type, (unsigned long long)qid.path, qid.version);

	p9pdu_writef(out, "Q", &qid);
	return 0;
}
// TODO: request_mask
static int p9_op_getattr(struct p9_server *s, struct p9_fcall *in,
						 struct p9_fcall *out)
{
	int err;
	u32 fid_val;
	u64 request_mask;
	struct p9_server_fid *fid;
	struct kstat st;
	struct p9_qid qid;

	p9pdu_readf(in, "dq", &fid_val, &request_mask);
	p9s_debug("getattr : fid %d, request_mask %lld\n",
			fid_val, request_mask);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	err = gen_qid(&fid->path, &qid, &st);
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

static int p9_op_clunk(struct p9_server *s, struct p9_fcall *in,
					   struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_server_fid *fid;

	p9pdu_readf(in, "d", &fid_val);
	p9s_debug("destroy fid : %d\n", fid_val);
	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return 0;

	if (!IS_ERR_OR_NULL(fid->filp))
		filp_close(fid->filp, NULL);

	rb_erase(&fid->node, &s->fids);
	dput(fid->path.dentry);
	kfree(fid);
	p9s_debug("fid : %d destroyed\n", fid_val);
	return 0;
}

static int p9_op_walk(struct p9_server *s, struct p9_fcall *in,
					  struct p9_fcall *out)
{
	int err;
	size_t t;
	u16 nwqid, nwname;
	u32 fid_val, newfid_val;
	char *name;
	struct p9_qid qid;
	struct p9_server_fid *fid, *newfid;
	struct path new_path;
	struct dentry *dentry;

	p9pdu_readf(in, "ddw", &fid_val, &newfid_val, &nwname);

	/* Get the indicated fid. */
	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	/* Check if the newfid already exists. */
	newfid = lookup_fid(s, newfid_val);
	if (!IS_ERR(newfid) && newfid_val != fid_val)
		return -EEXIST;

	p9s_debug("walk : fids %d,%d nwname %ud\n", fid_val,
			newfid_val, nwname);

	new_path = fid->path;
	nwqid = 0;
	out->size += sizeof(u16);

	if (nwname) {
		dentry = fid->path.dentry;
		for (; nwqid < nwname; nwqid++) {
			p9pdu_readf(in, "s", &name);
			p9s_debug("walk : name %s\n", name);

			/* ".." is not allowed. */
			if (name[0] == '.' && name[1] == '.' && name[2] == '\0')
				break;

			// TODO: lock may be needed
			new_path.dentry =
				lookup_one_len(name, dentry, strlen(name));
			kfree(name);
			if (IS_ERR(new_path.dentry)) {
				return PTR_ERR(new_path.dentry);
			} else if (d_really_is_negative(new_path.dentry)) {
				return -ENOENT;
			}
			err = gen_qid(&new_path, &qid, NULL);
			if (err)
				return err;

			// TODO: verify if it's valid
			p9pdu_writef(out, "Q", &qid);
			p9s_debug("walk : qid = [%d] %x.%llx.%x\n",
					nwqid, qid.type, qid.path, qid.version);

			if (nwqid)
				dput(dentry);
			dentry = new_path.dentry;
		}

		if (!nwqid)
			return err;

	} else {
		/* If nwname is 0, it's equivalent to walking
		 * to the current directory. */
		err = gen_qid(&new_path, &qid, NULL);
		if (err)
			return err;

		p9pdu_writef(out, "Q", &qid);
		p9s_debug("walk : qid = %x.%llx.%x\n",
				qid.type, qid.path, qid.version);
	}

	if (fid_val == newfid_val) {
		fid->path = new_path;
	} else {
		newfid = new_fid(s, newfid_val, &new_path);
		if (IS_ERR(newfid))
			return PTR_ERR(newfid);
		newfid->uid = fid->uid;
	}

	t = out->size;
	out->size = P9_PDU_HDR_LEN;
	p9pdu_writef(out, "w", nwqid);
	out->size = t;
	p9s_debug("walked : nwqid %d\n", nwqid);
	return 0;
}

static int p9_op_statfs(struct p9_server *s, struct p9_fcall *in,
						struct p9_fcall *out)
{
	int err;
	u64 fsid;
	u32 fid_val;
	struct p9_server_fid *fid;
	struct kstatfs st;

	p9pdu_readf(in, "d", &fid_val);
	p9s_debug("Stat : fid %d\n", fid_val);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	err = vfs_statfs(&fid->path, &st);
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
static int build_openflags(int flags)
{
	flags &= ~(O_NOCTTY | FASYNC | O_CREAT | O_DIRECT);
	flags |= O_NOFOLLOW;
	return flags;
}

static int p9_op_open(struct p9_server *s, struct p9_fcall *in,
					  struct p9_fcall *out)
{
	int err;
	u32 fid_val, flags;
	struct p9_qid qid;
	struct p9_server_fid *fid;

	p9pdu_readf(in, "dd", &fid_val, &flags);
	p9s_debug("open : qid = %x.%llx.%x\n",
			qid.type, (unsigned long long)qid.path, qid.version);

	fid = lookup_fid(s, fid_val);

	if (IS_ERR(fid))
		return PTR_ERR(fid);
	else if (fid->filp)
		// TODO: verify if being error is also considered busy
		return -EBUSY;

	err = gen_qid(&fid->path, &qid, NULL);

	if (err)
		return err;

	fid->filp =
		dentry_open(&fid->path, build_openflags(flags), current_cred());
	if (IS_ERR(fid->filp)) {
		fid->filp = NULL;
		return PTR_ERR(fid->filp);
	}

	/* FIXME!! need ot send proper iounit  */
	p9pdu_writef(out, "Qd", &qid, 0L);
	p9s_debug("opened : qid = %x.%llx.%x\n",
			qid.type, (unsigned long long)qid.path, qid.version);

	return 0;
}

static int p9_op_create(struct p9_server *s, struct p9_fcall *in,
						struct p9_fcall *out)
{
	int err;
	char *name;
	u32 dfid_val, flags, mode, gid;
	struct p9_qid qid;
	struct p9_server_fid *dfid;
	struct path new_path;
	struct file *new_filp;

	p9pdu_readf(in, "d", &dfid_val);

	dfid = lookup_fid(s, dfid_val);

	if (IS_ERR(dfid))
		return PTR_ERR(dfid);
	else if (dfid->filp)
		return -EBUSY;

	p9pdu_readf(in, "sddd", &name, &flags, &mode, &gid);
	p9s_debug("create : fid %d name %s flags %d mode %d gid %d\n",
			dfid_val, name, flags, mode, gid);

	new_path.mnt = dfid->path.mnt;
	new_path.dentry = lookup_one_len(name, dfid->path.dentry, strlen(name));

	kfree(name);

	if (IS_ERR(new_path.dentry))
		return PTR_ERR(new_path.dentry);
	else if (d_really_is_positive(new_path.dentry)) {
		pr_notice("create: postive dentry!\n");
		return -EEXIST;
	}

	err = vfs_create(dfid->path.dentry->d_inode, new_path.dentry,
					 mode, build_openflags(flags) & O_EXCL);
	if (err)
		return err;

	set_owner(new_path.dentry, dfid->uid, gid);
	new_filp = dentry_open(&new_path,
		build_openflags(flags) | O_CREAT, current_cred());
	if (IS_ERR(new_filp))
		return PTR_ERR(new_filp);

	err = gen_qid(&new_path, &qid, NULL);
	if (err)
		goto err;

	dfid->path = new_path;
	dfid->filp = new_filp;

	p9pdu_writef(out, "Qd", &qid, 0L);
	p9s_debug("created : qid = %x.%llx.%x\n",
			qid.type, (unsigned long long)qid.path, qid.version);

	return 0;
err:
	filp_close(new_filp, NULL);
	return err;
}

struct p9_readdir_ctx {
	size_t i, count;
	int err;
	bool is_root;

	struct dir_context ctx;
	struct path *parent;
	struct p9_fcall *out;

	struct {
		struct p9_qid qid;
		char name[MAX_FILE_NAME];
		unsigned int d_type;
	} prev;
};

/*
 *	The callback function from iterate_dir.
 *
 *	Note: returning non-zero terminates the executing of iterate_dir.
 *		  However, iterate_dir will still return zero.
 *
 *	Note: weird logic: the offset is of the previous element. So we
 *		  deal with the previous element in each iteration.
 */

static int p9_readdir_cb(struct dir_context *ctx, const char *name, int namlen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	size_t write_len;
	struct path path;
	struct p9_readdir_ctx *_ctx =
		container_of(ctx, struct p9_readdir_ctx, ctx);

	write_len = sizeof(u8) +	// qid.type
				sizeof(u32) +	// qid.version
				sizeof(u64) +	// qid.path
				sizeof(u64) +	// offset
				sizeof(u8) +	// d_type
				sizeof(u16) +	// name.len
				namlen;					// name

	if (namlen >= MAX_FILE_NAME) {
		pr_err("max file name is %d, this file name is %d\n",
				MAX_FILE_NAME - 1, namlen);
		return 1;
	}
	// If writing this dirent would cause an overflow,
	// terminate iterate_dir.
	if (_ctx->i + write_len > _ctx->count)
		return 1;

	// Writing the previous element with current offset
	if (_ctx->i) {
		p9s_debug("readdir_cb: offset %lld	d_type %d  name %s\n",
			offset, _ctx->prev.d_type, _ctx->prev.name);
		p9pdu_writef(_ctx->out, "Qqbs", &_ctx->prev.qid, (u64) offset,
			_ctx->prev.d_type, _ctx->prev.name);
	}

	/* Prepare the dirent for the next iteration. */

	path.mnt = _ctx->parent->mnt;

	// lookup_one_len doesn't allow the lookup of "." and "..".i
	// We have to do it ourselves.
	if (namlen == 1 && name[0] == '.')
		path.dentry = _ctx->parent->dentry;
	else if (namlen == 2 && name[0] == '.' && name[1] == '.')
		// No ".." allowed on the mount root
		path.dentry = _ctx->is_root ?
			_ctx->parent->dentry : _ctx->parent->dentry->d_parent;
	else
		path.dentry =
			lookup_one_len(name, _ctx->parent->dentry, namlen);

	if (IS_ERR(path.dentry)) {
		_ctx->err = PTR_ERR(path.dentry);
		goto out;
	} else if (d_really_is_negative(path.dentry)) {
		_ctx->err = -ENOENT;
		goto out;
	}

	_ctx->err = gen_qid(&path, &_ctx->prev.qid, NULL);
	if (_ctx->err)
		goto out;

	strncpy(_ctx->prev.name, name, namlen);
	_ctx->prev.name[namlen] = 0;
	_ctx->prev.d_type = d_type;

	_ctx->i += write_len;
out:
	return _ctx->err;
}

static int p9_op_readdir(struct p9_server *s, struct p9_fcall *in,
						 struct p9_fcall *out)
{
	int err;
	u32 dfid_val, count;
	u64 offset;
	struct p9_server_fid *dfid;
	struct p9_readdir_ctx _ctx = {
		.ctx.actor = p9_readdir_cb
	};

	p9pdu_readf(in, "dqd", &dfid_val, &offset, &count);
	p9s_debug("readdir : fid %d offset %llu count %d\n",
			dfid_val, (unsigned long long) offset, count);

	dfid = lookup_fid(s, dfid_val);
	if (IS_ERR(dfid))
		return PTR_ERR(dfid);

	if (IS_ERR_OR_NULL(dfid->filp))
		return -EBADF;

	err = vfs_llseek(dfid->filp, offset, SEEK_SET);
	if (err < 0)
		return err;

	_ctx.parent = &dfid->path;
	_ctx.out = out;
	_ctx.i = 0;
	_ctx.count = count;
	_ctx.err = 0;
	_ctx.is_root = (dfid->path.dentry == s->root.dentry);

	out->size += sizeof(u32);	// Make room for count

	err = iterate_dir(dfid->filp, &_ctx.ctx);
	if (err)
		return err;
	if (_ctx.err)
		return _ctx.err;

	// Write the last element
	if (_ctx.i)
		p9pdu_writef(out, "Qqbs", &_ctx.prev.qid, (u64) _ctx.ctx.pos,
				_ctx.prev.d_type, _ctx.prev.name);

	out->size = P9_PDU_HDR_LEN;
	p9pdu_writef(out, "d", _ctx.i); // Total bytes written
	out->size += _ctx.i;

	return 0;
}

static int p9_op_read(struct p9_server *s, struct p9_fcall *in,
					  struct p9_fcall *out)
{
	u32 fid_val, count;
	u64 offset;
	ssize_t len;
	struct p9_server_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);
	p9s_debug("read : fid %d offset %llu count %d\n",
			fid_val, (unsigned long long) offset, count);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (IS_ERR_OR_NULL(fid->filp))
		return -EBADF;

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

static int p9_op_readv(struct p9_server *s, struct p9_fcall *in,
			struct p9_fcall *out, struct iov_iter *data)
{
	u32 fid_val, count;
	u64 offset;
	ssize_t len;
	struct p9_server_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (IS_ERR_OR_NULL(fid->filp))
		return -EBADF;

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

static int p9_op_setattr(struct p9_server *s, struct p9_fcall *in,
						 struct p9_fcall *out)
{
	int err = 0;
	u32 fid_val;
	struct p9_server_fid *fid;
	struct p9_iattr_dotl p9attr;
	struct iattr iattr;
	struct dentry *dentry;

	p9pdu_readf(in, "dddugqqqqq", &fid_val,
				&p9attr.valid, &p9attr.mode,
				&p9attr.uid, &p9attr.gid, &p9attr.size,
				&p9attr.atime_sec, &p9attr.atime_nsec,
				&p9attr.mtime_sec, &p9attr.mtime_nsec);
	p9s_debug("setattr : fid %d, valid %x, mode %x, uid %d, gid %d\n"
			"size %lld, at_sec %lld, at_nsec %lld\n"
			"mt_sec %lld, mt_nsec %lld\n",
			fid_val, p9attr.valid, p9attr.mode,
				p9attr.uid.val, p9attr.gid.val, p9attr.size,
				p9attr.atime_sec, p9attr.atime_nsec,
				p9attr.mtime_sec, p9attr.mtime_nsec);


	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);
	dentry = fid->path.dentry;
	memset(&iattr, 0, sizeof(struct iattr));

	if (p9attr.valid & ATTR_MODE) {
		iattr.ia_valid |= ATTR_MODE | ATTR_CTIME;
		iattr.ia_mode = p9attr.mode;
		iattr.ia_ctime = current_time(dentry->d_inode);
	}

	if (p9attr.valid & ATTR_ATIME) {
		iattr.ia_valid |= ATTR_ATIME;
		if (p9attr.valid & ATTR_ATIME_SET) {
			iattr.ia_valid |= ATTR_ATIME_SET;
			iattr.ia_atime.tv_sec = p9attr.atime_sec;
			iattr.ia_atime.tv_nsec = p9attr.atime_nsec;
		} else
			iattr.ia_atime.tv_nsec = UTIME_NOW;
	} else
		iattr.ia_atime.tv_nsec = UTIME_OMIT;

	if (p9attr.valid & ATTR_MTIME) {
		iattr.ia_valid |= ATTR_MTIME;
		if (p9attr.valid & ATTR_MTIME_SET) {
			iattr.ia_valid |= ATTR_MTIME_SET;
			iattr.ia_mtime.tv_sec = p9attr.mtime_sec;
			iattr.ia_mtime.tv_nsec = p9attr.mtime_nsec;
		} else
			iattr.ia_mtime.tv_nsec = UTIME_NOW;
	} else
		iattr.ia_mtime.tv_nsec = UTIME_OMIT;

	if (p9attr.valid & ATTR_UID) {
		iattr.ia_valid |= ATTR_UID;
		iattr.ia_uid.val = p9attr.uid.val;
	}
	if (p9attr.valid & ATTR_GID) {
		iattr.ia_valid |= ATTR_GID;
		iattr.ia_gid.val = p9attr.gid.val;
	}
	if (p9attr.valid & ATTR_CTIME) {
		iattr.ia_valid |= ATTR_CTIME;
		iattr.ia_ctime = current_time(dentry->d_inode);
	}
	if (iattr.ia_valid) {
		inode_lock(dentry->d_inode);
		err = notify_change(dentry, &iattr, NULL);
		inode_unlock(dentry->d_inode);
		if (err < 0)
			return err;
	}
	if (p9attr.valid & ATTR_SIZE) {
		err = vfs_truncate(&fid->path, p9attr.size);
		if (err < 0)
			return err;
	}
	p9s_debug("setattr : fid %d\n", fid->fid);
	return 0;
}

static int p9_op_write(struct p9_server *s, struct p9_fcall *in,
		struct p9_fcall *out)
{
	u64 offset;
	u32 fid_val, count;
	ssize_t len;
	struct p9_server_fid *fid;
	mm_segment_t fs;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);
	p9s_debug("write : fid %d offset %llu count %d\n",
			fid_val, (unsigned long long) offset, count);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (IS_ERR_OR_NULL(fid->filp))
		return -EBADF;

	fs = get_fs();
	set_fs(KERNEL_DS);
	len = vfs_write(fid->filp, in->sdata + in->offset, count, &offset);
	set_fs(fs);

	if (len < 0)
		return len;

	p9pdu_writef(out, "d", (u32) len);
	p9s_debug("wrote : count %d\n", count);
	return 0;
}

static int p9_op_writev(struct p9_server *s, struct p9_fcall *in,
				struct p9_fcall *out, struct iov_iter *data)
{
	u64 offset;
	u32 fid_val, count;
	ssize_t len;
	struct p9_server_fid *fid;

	p9pdu_readf(in, "dqd", &fid_val, &offset, &count);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	if (IS_ERR_OR_NULL(fid->filp))
		return -EBADF;

	if (data->count > count)
		data->count = count;

	len = vfs_iter_write(fid->filp, data, &offset);

	if (len < 0)
		return len;

	p9pdu_writef(out, "d", (u32) len);
	return 0;
}

static int p9_op_unlinkat(struct p9_server *s, struct p9_fcall *in,
						struct p9_fcall *out)
{
	u32 fid_val;
	char *name;
	struct p9_server_fid *fid;
	struct dentry *dentry;
	int err;

	p9pdu_readf(in, "ds", &fid_val, &name);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9s_debug("unlinkat : fid %d, name %s\n", fid_val, name);
	dentry = lookup_one_len(name, fid->path.dentry, strlen(name));
	kfree(name);
	if (d_really_is_negative(dentry))
		return -ENOENT;

	if (S_ISDIR(dentry->d_inode->i_mode))
		err = vfs_rmdir(dentry->d_parent->d_inode, dentry);
	else
		err = vfs_unlink(dentry->d_parent->d_inode, dentry, NULL);

	p9s_debug("unlinkat : success\n");
	return err;
}

static int p9_op_remove(struct p9_server *s, struct p9_fcall *in,
						struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_server_fid *fid;
	struct dentry *dentry;
	int err;

	p9pdu_readf(in, "d", &fid_val);
	p9s_debug("remove : fid %d\n", fid_val);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	dentry = fid->path.dentry;

	// TODO: null check
	if (d_really_is_negative(dentry))
		return -ENOENT;

	if (S_ISDIR(dentry->d_inode->i_mode))
		err = vfs_rmdir(dentry->d_parent->d_inode, dentry);
	else
		err = vfs_unlink(dentry->d_parent->d_inode, dentry, NULL);

	rb_erase(&fid->node, &s->fids);
	p9s_debug("fid : %d is removed\n", fid->fid);
	return err;
}

// TODO: resolve this hack
extern int vfs_path_lookup(struct dentry *dentry, struct vfsmount *mnt,
			const char *name, unsigned int flags,
			struct path *path);

static int p9_op_rename(struct p9_server *s, struct p9_fcall *in,
						struct p9_fcall *out)
{
	int err;
	u32 fid_val, newfid_val;
	char *path;
	struct p9_server_fid *fid, *newfid;
	struct dentry *old_dentry, *new_dentry;
	struct path new_path;

	p9pdu_readf(in, "d", &fid_val);

	fid = lookup_fid(s, fid_val);

	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "ds", &newfid_val, &path);
	p9s_debug("rename : fid %d newfid %d\n", fid_val, newfid_val);

	err = vfs_path_lookup(fid->path.dentry, fid->path.mnt, path,
		LOOKUP_RENAME_TARGET, &new_path);
	if (err < 0) {
		kfree(path);
		return err;
	}

	// TODO: security: new dir under the root

	newfid = new_fid(s, newfid_val, &new_path);
	p9s_debug("rename : newfid %d\n", newfid->fid);

	kfree(path);

	if (IS_ERR(newfid))
		return PTR_ERR(newfid);

	old_dentry = fid->path.dentry;
	new_dentry = newfid->path.dentry;

	return vfs_rename(old_dentry->d_parent->d_inode, old_dentry,
		new_dentry->d_parent->d_inode, new_dentry, NULL, 0);
}

static int p9_op_renameat(struct p9_server *s, struct p9_fcall *in,
						struct p9_fcall *out)
{
	int err = 0;
	u32 oldfid_val, newfid_val;
	char *oldname = NULL, *newname = NULL;
	struct p9_server_fid *oldfid, *newfid;
	struct dentry *old_dentry, *new_dentry;

	p9pdu_readf(in, "dsds", &oldfid_val,  &oldname, &newfid_val, &newname);

	oldfid = lookup_fid(s, oldfid_val);
	if (IS_ERR(oldfid)) {
		err = PTR_ERR(oldfid);
		goto out;
	}

	newfid = lookup_fid(s, newfid_val);
	if (IS_ERR(newfid)) {
		err = PTR_ERR(newfid);
		goto out;
	}

	p9s_debug("renameat: oldfid %d, oldname %s, newfid %d, newname %s\n",
			oldfid_val, oldname, newfid_val, newname);

	old_dentry = lookup_one_len(oldname, oldfid->path.dentry,
					 strlen(oldname));
	if (IS_ERR(old_dentry)) {
		err = PTR_ERR(old_dentry);
		goto out;
	} else if (!d_really_is_positive(old_dentry)) {
		pr_err("renameat: source file %s doesn't exist!\n", oldname);
		err = -ENOENT;
		goto out;
	}

	new_dentry = lookup_one_len(newname, newfid->path.dentry,
					 strlen(newname));
	if (IS_ERR(new_dentry)) {
		err = PTR_ERR(new_dentry);
		goto out;
	} else if (d_really_is_positive(new_dentry)) {
		pr_err("renameat: destiny file %s exists!\n", newname);
		err = -EEXIST;
		goto out;
	}
	p9s_debug("renameat: call vfs_rename\n");

	err = vfs_rename(old_dentry->d_parent->d_inode, old_dentry,
				new_dentry->d_parent->d_inode, new_dentry,
				NULL, 0);
out:
	kfree(oldname);
	kfree(newname);
	return err;
}

static int p9_op_mkdir(struct p9_server *s, struct p9_fcall *in,
					   struct p9_fcall *out)
{
	int err;
	u32 dfid_val, mode, gid;
	char *name;
	struct p9_qid qid;
	struct p9_server_fid *dfid;
	struct path new_path;

	p9pdu_readf(in, "d", &dfid_val);

	dfid = lookup_fid(s, dfid_val);

	if (IS_ERR(dfid))
		return PTR_ERR(dfid);

	p9pdu_readf(in, "sdd", &name, &mode, &gid);
	p9s_debug("mkdir : fid %d name %s mode %d gid %d\n",
			dfid->fid, name, mode, gid);

	new_path.mnt = dfid->path.mnt;
	new_path.dentry = lookup_one_len(name, dfid->path.dentry, strlen(name));

	kfree(name);

	if (IS_ERR(new_path.dentry)) {
		return PTR_ERR(new_path.dentry);
	} else if (d_really_is_positive(new_path.dentry)) {
		p9s_debug("mkdir : postive dentry!\n");
		return -EEXIST;
	}

	// TODO: verify dfid's inode is valid

	err = vfs_mkdir(dfid->path.dentry->d_inode, new_path.dentry, mode);
	if (err < 0)
		return err;
	set_owner(new_path.dentry, dfid->uid, gid);
	err = gen_qid(&new_path, &qid, NULL);
	if (err)
		return err;

	p9pdu_writef(out, "Qd", &qid, 0L);
	p9s_debug("mkdir : qid = %x.%llx.%x\n",
			qid.type, (unsigned long long)qid.path, qid.version);

	return 0;
}

static int p9_op_symlink(struct p9_server *s, struct p9_fcall *in,
						 struct p9_fcall *out)
{
	int err;
	u32 fid_val, gid;
	struct p9_qid qid;
	struct p9_server_fid *fid;
	char *name, *dst;
	struct path symlink_path;

	p9pdu_readf(in, "d", &fid_val);
	p9s_debug("symlink : fid %d\n", fid_val);

	fid = lookup_fid(s, fid_val);

	if (IS_ERR(fid))
		return PTR_ERR(fid);

	p9pdu_readf(in, "ssd", &name, &dst, &gid);
	p9s_debug("symlink : name %s  dst %s\n", name, dst);

	symlink_path.mnt = fid->path.mnt;
	symlink_path.dentry =
		lookup_one_len(name, fid->path.dentry, strlen(name));
	kfree(name);

	if (d_really_is_positive(symlink_path.dentry)) {
		kfree(dst);
		return -EEXIST;
	}

	// TODO: security: symlink target must be strictly under the root

	err = vfs_symlink(fid->path.dentry->d_inode, symlink_path.dentry, dst);

	kfree(dst);

	if (err < 0)
		return err;

	err = gen_qid(&symlink_path, &qid, NULL);
	if (err)
		return err;

	p9pdu_writef(out, "Q", &qid);
	p9s_debug("symlink : qid = %x.%llx.%x\n",
			qid.type, (unsigned long long)qid.path, qid.version);

	return 0;
}

static int p9_op_link(struct p9_server *s, struct p9_fcall *in,
					  struct p9_fcall *out)
{
	char *name;
	u32 dfid_val, fid_val;
	struct p9_server_fid *dfid, *fid;
	struct dentry *new_dentry;

	p9pdu_readf(in, "dd", &dfid_val, &fid_val);
	p9s_debug("link : dfid %d fid %d\n", dfid_val, fid_val);

	fid = lookup_fid(s, fid_val);

	if (IS_ERR(fid))
		return PTR_ERR(fid);

	dfid = lookup_fid(s, dfid_val);

	if (IS_ERR(dfid))
		return PTR_ERR(dfid);

	p9pdu_readf(in, "s", &name);
	p9s_debug("link : name %s\n", name);

	new_dentry = lookup_one_len(name, dfid->path.dentry, strlen(name));

	kfree(name);

	if (IS_ERR(new_dentry)) {
		return PTR_ERR(new_dentry);
	} else if (d_really_is_positive(new_dentry)) {
		pr_notice("link: postive dentry!\n");
		return -EEXIST;
	}

	// TODO: make sure dfid dentry is positive

	return vfs_link(fid->path.dentry, dfid->path.dentry->d_inode,
			new_dentry, NULL);
}
// TODO: put path
static int p9_op_readlink(struct p9_server *s, struct p9_fcall *in,
						  struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_server_fid *fid;
	struct dentry *dentry;
	const char *link = NULL;
	DEFINE_DELAYED_CALL(done);

	p9pdu_readf(in, "d", &fid_val);
	p9s_debug("readlink : fid %d\n", fid_val);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	dentry = fid->path.dentry;

	// TODO: security check
	link = vfs_get_link(dentry, &done);
	if (IS_ERR(link))
		return PTR_ERR(link);

	p9pdu_writef(out, "s", link);
	kfree(link);
	p9s_debug("readlink : path %s\n", link);

	return 0;
}

static int p9_op_fsync(struct p9_server *s, struct p9_fcall *in,
					   struct p9_fcall *out)
{
	int err = -EBADFD;
	u32 fid_val, datasync;
	struct p9_server_fid *fid;

	p9pdu_readf(in, "dd", &fid_val, &datasync);
	p9s_debug("fsync : fid %d datasync:%d\n", fid_val, datasync);

	fid = lookup_fid(s, fid_val);
	if (IS_ERR(fid))
		return PTR_ERR(fid);

	// TODO: verify that filp can't be error

	if (!IS_ERR_OR_NULL(fid->filp))
		err = vfs_fsync(fid->filp, datasync);

	p9s_debug("fsync : fid %d\n", fid->fid);

	return err;
}

// TODO: gid
static int p9_op_mknod(struct p9_server *s, struct p9_fcall *in,
					   struct p9_fcall *out)
{
	int err;
	char *name;
	u32 dfid_val, mode, major, minor, gid;
	struct p9_qid qid;
	struct p9_server_fid *dfid;
	struct path new_path;

	p9pdu_readf(in, "d", &dfid_val);

	dfid = lookup_fid(s, dfid_val);

	if (IS_ERR(dfid))
		return PTR_ERR(dfid);

	p9pdu_readf(in, "sdddd", &name, &mode, &major, &minor, &gid);
	p9s_debug("mknod : name %s mode %d major %d minor %d\n",
		name, mode, major, minor);

	new_path.mnt = dfid->path.mnt;
	new_path.dentry = lookup_one_len(name, dfid->path.dentry, strlen(name));

	kfree(name);

	if (IS_ERR(new_path.dentry)) {
		return PTR_ERR(new_path.dentry);
	} else if (d_really_is_positive(new_path.dentry)) {
		pr_notice("mknod: postive dentry!\n");
		return -EEXIST;
	}

	err = vfs_mknod(dfid->path.dentry->d_inode, new_path.dentry,
			mode, MKDEV(major, minor));

	if (err < 0)
		return err;

	set_owner(new_path.dentry, dfid->uid, gid);

	err = gen_qid(&new_path, &qid, NULL);
	if (err)
		return err;

	p9pdu_writef(out, "Q", &qid);
	p9s_debug("mknod : qid = %x.%llx.%x\n",
			qid.type, (unsigned long long)qid.path, qid.version);

	return 0;
}

static int p9_op_lock(struct p9_server *s, struct p9_fcall *in,
					  struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_flock flock;

	p9pdu_readf(in, "dbdqqds", &fid_val, &flock.type,
				&flock.flags, &flock.start, &flock.length,
				&flock.proc_id, &flock.client_id);
	p9s_debug("lock : fid %d type %i flags %d,\
			start %lld length %lld proc_id %d client_id %s\n",
			fid_val, flock.type, flock.flags, flock.start,
			flock.length, flock.proc_id, flock.client_id);

	kfree(flock.client_id);

	/* Just return success */
	p9pdu_writef(out, "d", (u8) P9_LOCK_SUCCESS);
	return 0;
}

static int p9_op_getlock(struct p9_server *s, struct p9_fcall *in,
						 struct p9_fcall *out)
{
	u32 fid_val;
	struct p9_getlock glock;

	p9pdu_readf(in, "dbqqds", &fid_val, &glock.type,
				&glock.start, &glock.length, &glock.proc_id,
				&glock.client_id);
	p9s_debug("getlock : fid %d, type %i start %lld,\
		length %lld proc_id %d client_id %s\n", fid_val, glock.type,
		glock.start, glock.length, glock.proc_id, glock.client_id);

	/* Just return success */
	glock.type = F_UNLCK;
	p9pdu_writef(out, "bqqds", glock.type,
				 glock.start, glock.length, glock.proc_id,
				 glock.client_id);
	p9s_debug("getlock : type %i start %lld,\
		length %lld proc_id %d client_id %s\n", glock.type,
		glock.start, glock.length, glock.proc_id, glock.client_id);

	kfree(glock.client_id);
	return 0;
}

static int p9_op_flush(struct p9_server *s, struct p9_fcall *in,
					   struct p9_fcall *out)
{
	u16 tag, oldtag;

	p9pdu_readf(in, "ww", &tag, &oldtag);
	p9s_debug("flush : tag %d\n", oldtag);
	p9pdu_writef(out, "w", tag);

	return 0;
}

typedef int p9_server_op(struct p9_server *s, struct p9_fcall *in,
			struct p9_fcall *out);

static p9_server_op *p9_ops[] = {
//	[P9_TLERROR]	  = p9_op_error,	// Not used
	[P9_TSTATFS]	  = p9_op_statfs,
	[P9_TLOPEN]		  = p9_op_open,
	[P9_TLCREATE]	  = p9_op_create,
	[P9_TSYMLINK]	  = p9_op_symlink,
	[P9_TMKNOD]		  = p9_op_mknod,
	[P9_TRENAME]	  = p9_op_rename,
	[P9_TREADLINK]	  = p9_op_readlink,
	[P9_TGETATTR]	  = p9_op_getattr,
	[P9_TSETATTR]	  = p9_op_setattr,
//	[P9_TXATTRWALK]   = p9_op_xattrwalk,	// Not implemented
//	[P9_TXATTRCREATE] = p9_op_xattrcreate,	// Not implemented
	[P9_TREADDIR]	  = p9_op_readdir,
	[P9_TFSYNC]		  = p9_op_fsync,
	[P9_TLOCK]		  = p9_op_lock,
	[P9_TGETLOCK]	  = p9_op_getlock,
	[P9_TLINK]		  = p9_op_link,
	[P9_TMKDIR]		  = p9_op_mkdir,
	[P9_TRENAMEAT]	  = p9_op_renameat,
	[P9_TUNLINKAT]	  = p9_op_unlinkat,
//Not supported. No easy way to implement besides syscalls
	[P9_TVERSION]	  = p9_op_version,
//	[P9_TAUTH]		  = p9_op_auth, // Not implemented
	[P9_TATTACH]	  = p9_op_attach,
//	[P9_TERROR]		  = p9_op_error,		// Not used
	[P9_TFLUSH]		  = p9_op_flush,
	[P9_TWALK]		  = p9_op_walk,
//	[P9_TOPEN]		  = p9_op_open, // Not supported in 9P2000.L
//	[P9_TCREATE]	  = p9_op_create,	// Not supported in 9P2000.L
	[P9_TREAD]		  = p9_op_read,
	[P9_TWRITE]		  = p9_op_write,
	[P9_TCLUNK]		  = p9_op_clunk,
	[P9_TREMOVE]	  = p9_op_remove,
//	[P9_TSTAT]		  = p9_op_stat, // Not implemented
//	[P9_TWSTAT]		  = p9_op_wstat,	// Not implemented
};

static const char * const translate[] = {
	[P9_TLERROR]	  = "error",
	[P9_TSTATFS]	  = "statfs",
	[P9_TLOPEN]		  = "open",
	[P9_TLCREATE]	  = "create",
	[P9_TSYMLINK]	  = "symlink",
	[P9_TMKNOD]		  = "mknod",
	[P9_TRENAME]	  = "rename",
	[P9_TREADLINK]	  = "readlink",
	[P9_TGETATTR]	  = "getattr",
	[P9_TSETATTR]	  = "setattr",
	[P9_TXATTRWALK]   = "xattrwalk",
	[P9_TXATTRCREATE] = "xattrcreate",
	[P9_TREADDIR]	  = "readdir",
	[P9_TFSYNC]		  = "fsync",
	[P9_TLOCK]		  = "lock",
	[P9_TGETLOCK]	  = "getlock",
	[P9_TLINK]		  = "link",
	[P9_TMKDIR]		  = "mkdir",
	[P9_TRENAMEAT]	  = "renameat",
	[P9_TUNLINKAT]	  = "unlinkat",
	[P9_TVERSION]	  = "version",
	[P9_TAUTH]		  = "auth",
	[P9_TATTACH]	  = "attach",
	[P9_TERROR]		  = "error",
	[P9_TFLUSH]		  = "flush",
	[P9_TWALK]		  = "walk",
	[P9_TOPEN]		  = "open",
	[P9_TCREATE]	  = "create",
	[P9_TREAD]		  = "read",
	[P9_TWRITE]		  = "write",
	[P9_TCLUNK]		  = "clunk",
	[P9_TREMOVE]	  = "remove",
	[P9_TSTAT]		  = "stat",
	[P9_TWSTAT]		  = "wstat",
};

struct p9_header {
	uint32_t size;
	uint8_t id;
	uint16_t tag;
} __packed;

struct p9_io_header {
	uint32_t size;
	uint8_t id;
	uint16_t tag;
	uint32_t fid;
	uint64_t offset;
	uint32_t count;
} __packed;

static struct p9_fcall *new_pdu(size_t size)
{
	struct p9_fcall *pdu;

	pdu = kmalloc(sizeof(struct p9_fcall) + size, GFP_KERNEL);
	pdu->size = 0;	// write offset
	pdu->offset = 0;	// read offset
	pdu->capacity = size;
	pdu->sdata = (void *)pdu + sizeof(struct p9_fcall);
	// Make the data area right after the pdu structure

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

void do_9p_request(struct p9_server *s, struct iov_iter *req,
		struct iov_iter *resp)
{
	int err = -EOPNOTSUPP;
	u8 cmd;
	struct iov_iter data;
	struct p9_fcall *in, *out;
	struct p9_io_header *hdr;
	// Assume the operation is an IO operation to save additional
	// copy_from_iter.

	in = new_pdu(req->count);
	out = new_pdu(resp->count);

	pdu_fill(in, req, sizeof(struct p9_io_header));
	hdr = (struct p9_io_header *)in->sdata;

	in->offset = out->size = sizeof(struct p9_header);
	in->tag = out->tag = hdr->tag;
	in->id = cmd = hdr->id;
	out->id = hdr->id + 1;

	pr_notice("do_9p_request: %s! %d\n", translate[cmd], in->tag);

	if (cmd < ARRAY_SIZE(p9_ops) && p9_ops[cmd]) {
		if (cmd == P9_TREAD || cmd == P9_TWRITE) {
			/* Do zero-copy for large IO */
			if (hdr->count > 1024) {
				if (cmd == P9_TREAD) {
					iov_iter_clone(&data, resp);
					iov_iter_advance(&data,
						sizeof(struct p9_header) +
						sizeof(u32));
					resp->count = sizeof(struct p9_header) +
						sizeof(u32);

					err = p9_op_readv(s, in, out, &data);
				} else
					err = p9_op_writev(s, in, out, req);
			} else {
				if (cmd == P9_TWRITE) {
					pdu_fill(in, req, hdr->count);
					err = p9_op_write(s, in, out);
				} else
					err = p9_op_read(s, in, out);
			}
		} else {
			/* Copy the rest data */
			if (hdr->size > sizeof(struct p9_io_header))
				pdu_fill(in, req, hdr->size -
						sizeof(struct p9_io_header));

			err = p9_ops[cmd](s, in, out);
		}

		kfree(in);
	} else {
		if (cmd < ARRAY_SIZE(p9_ops))
			pr_warn("!!!not implemented: %s\n", translate[cmd]);
		else
			pr_warn("!!!cmd too large: %d\n", (u32) cmd);
	}

	if (err) {
		pr_err("9p request error: %d\n", err);
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

struct p9_server *p9_server_create(struct path *root)
{
	struct p9_server *s;

	pr_info("9p server create!\n");

	s = kmalloc(sizeof(struct p9_server), GFP_KERNEL);
	if (!s)
		return ERR_PTR(-ENOMEM);

	s->root = *root;
	s->fids = RB_ROOT;

	return s;
}

void p9_server_close(struct p9_server *s)
{
	if (!IS_ERR_OR_NULL(s))
		kfree(s);
}
