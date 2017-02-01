#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/slab.h>

#include <linux/virtio_9p.h>
#include <net/9p/9p.h>

#include "vhost.h"
#include "vhost-9p.h"

/* Max number of bytes transferred before requeueing the job.
 * Using this limit prevents one virtqueue from starving others. */
#define VHOST_9P_WEIGHT 0x80000

enum {
	VHOST_9P_FEATURES = VHOST_FEATURES | (1ULL << VIRTIO_9P_MOUNT_TAG)
};

/* Expects to be always run from workqueue - which acts as
 * read-size critical section for our kind of RCU. */
static void handle_vq(struct vhost_9p *n)
{
	struct vhost_virtqueue *vq = &n->vqs[VHOST_9P_VQ];
	unsigned out, in;
	int head;
	size_t out_len, in_len, total_len = 0;
	struct iov_iter req, resp;

	mutex_lock(&vq->mutex);
	vhost_disable_notify(&n->dev, vq);

	for (;;) {
		head = vhost_get_vq_desc(vq, vq->iov,
					 ARRAY_SIZE(vq->iov),
					 &out, &in,
					 NULL, NULL);

		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new? Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(&n->dev, vq))) {
				vhost_disable_notify(&n->dev, vq);
				continue;
			}
			break;
		}

		out_len = iov_length(vq->iov, out);
		in_len = iov_length(&vq->iov[out], in);

		iov_iter_init(&req, WRITE, vq->iov, out, out_len);
		iov_iter_init(&resp, READ, &vq->iov[out], in, in_len);

		do_9p_request(n->server, &req, &resp);

		vhost_add_used_and_signal(&n->dev, vq, head, in + out);

		total_len += out_len;
		if (unlikely(total_len >= VHOST_9P_WEIGHT)) {
			vhost_poll_queue(&vq->poll);
			break;
		}
	}

	mutex_unlock(&vq->mutex);
}

static void handle_vq_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						  poll.work);
	struct vhost_9p *n = container_of(vq->dev, struct vhost_9p, dev);

//	printk("VHOST_9P_HANDLE_KICK\n");

	handle_vq(n);
}

// TODO: execution flow review
static int vhost_9p_open(struct inode *inode, struct file *f)
{
	struct vhost_dev *dev;
	struct vhost_virtqueue **vqs;
	struct vhost_9p *n = kmalloc(sizeof *n, GFP_KERNEL);
	int err;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	char *str_root = "/home/guoyk/Desktop/vhost-9p/a";
	struct path root;

	printk("VHOST_9P_OPEN\n");

	if (!n)
		return -ENOMEM;

	vqs = kmalloc(VHOST_9P_VQ_MAX * sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kfree(n);
		return -ENOMEM;
	}

	dev = &n->dev;

	vqs[VHOST_9P_VQ] = &n->vqs[VHOST_9P_VQ];
	n->vqs[VHOST_9P_VQ].handle_kick = handle_vq_kick;
	vhost_dev_init(dev, vqs, VHOST_9P_VQ_MAX);

retry:
	err = kern_path(str_root, lookup_flags, &root);
	if (!err) {
		n->server = p9_server_create(&root);
		if (IS_ERR(n->server))
			err = PTR_ERR(n->server);
	}

	if (retry_estale(err, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}

	f->private_data = n;

	return err;
}

static void *vhost_9p_stop_vq(struct vhost_9p *n,
				struct vhost_virtqueue *vq)
{
	void *private;

	mutex_lock(&vq->mutex);
	private = vq->private_data;
	vq->private_data = NULL;
	mutex_unlock(&vq->mutex);
	return private;
}

static void vhost_9p_stop(struct vhost_9p *n, void **privatep)
{
	*privatep = vhost_9p_stop_vq(n, n->vqs + VHOST_9P_VQ);
}

static void vhost_9p_flush_vq(struct vhost_9p *n, int index)
{
	vhost_poll_flush(&n->vqs[index].poll);
}

static void vhost_9p_flush(struct vhost_9p *n)
{
	vhost_9p_flush_vq(n, VHOST_9P_VQ);
}

static int vhost_9p_release(struct inode *inode, struct file *f)
{
	struct vhost_9p *n = f->private_data;
	void *private;

	printk("VHOST_9P_RELEASE\n");

	vhost_9p_stop(n, &private);
	vhost_9p_flush(n);
	vhost_dev_cleanup(&n->dev, false);
	/* We do an extra flush before freeing memory,
	 * since jobs can re-queue themselves. */
	vhost_9p_flush(n);

	kfree(n);
	return 0;
}

static long vhost_9p_reset_owner(struct vhost_9p *n)
{
	void *priv = NULL;
	long err;
	struct vhost_memory *memory;

	mutex_lock(&n->dev.mutex);
	err = vhost_dev_check_owner(&n->dev);
	if (err)
		goto done;
	memory = vhost_dev_reset_owner_prepare();
	if (!memory) {
		err = -ENOMEM;
		goto done;
	}
	vhost_9p_stop(n, &priv);
	vhost_9p_flush(n);
	vhost_dev_reset_owner(&n->dev, memory);
done:
	mutex_unlock(&n->dev.mutex);
	return err;
}

static int vhost_9p_set_features(struct vhost_9p *n, u64 features)
{
	struct vhost_virtqueue *vq;

	mutex_lock(&n->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&n->dev)) {
		mutex_unlock(&n->dev.mutex);
		return -EFAULT;
	}
	vq = &n->vqs[VHOST_9P_VQ];
	mutex_lock(&vq->mutex);
	vq->acked_features = features;
	mutex_unlock(&vq->mutex);
	mutex_unlock(&n->dev.mutex);
	return 0;
}
/*
	if (root_dir[0] != '/')
		return -EINVAL;

	len = strlen(root_dir);
	if (len > PATH_MAX - 1)
		return -ENAMETOOLONG;

	// Check if base is dir
	err = lstat(root_dir, &st);
	if (err)
		return err;

	if (!S_ISDIR(st.mode))
		return -ENOTDIR;

	strncpy(s->base, root_dir, len);
	if (s->base[len - 1] == '/')
		s->base[len - 1] = '\0';

*/
static long vhost_9p_ioctl(struct file *f, unsigned int ioctl,
			     unsigned long arg)
{
	struct vhost_9p *n = f->private_data;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r;

	printk("virtio-9p ioctl: %d, %lx\n", ioctl, arg);

	switch (ioctl) {
	case VHOST_GET_FEATURES:
		features = VHOST_FEATURES;
		if (copy_to_user(featurep, &features, sizeof features))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, featurep, sizeof features))
			return -EFAULT;
		if (features & ~VHOST_9P_FEATURES)
			return -EOPNOTSUPP;
		return vhost_9p_set_features(n, features);
	case VHOST_RESET_OWNER:
		return vhost_9p_reset_owner(n);
	default:
		mutex_lock(&n->dev.mutex);
		r = vhost_dev_ioctl(&n->dev, ioctl, argp);
		if (r == -ENOIOCTLCMD)
			r = vhost_vring_ioctl(&n->dev, ioctl, argp);
		vhost_9p_flush(n);
		mutex_unlock(&n->dev.mutex);
		return r;
	}
}

#ifdef CONFIG_COMPAT
static long vhost_9p_compat_ioctl(struct file *f, unsigned int ioctl,
				   unsigned long arg)
{
	return vhost_9p_ioctl(f, ioctl, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations vhost_9p_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_9p_release,
	.unlocked_ioctl = vhost_9p_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = vhost_9p_compat_ioctl,
#endif
	.open           = vhost_9p_open,
	.llseek         = noop_llseek,
};

static struct miscdevice vhost_9p_misc = {
	MISC_DYNAMIC_MINOR,
	"vhost-9p",
	&vhost_9p_fops,
};

static int vhost_9p_init(void)
{
	return misc_register(&vhost_9p_misc);
}
module_init(vhost_9p_init);

static void vhost_9p_exit(void)
{
	misc_deregister(&vhost_9p_misc);
}
module_exit(vhost_9p_exit);

MODULE_VERSION("0.0.1");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuankai Guo");
MODULE_DESCRIPTION("In-kernel vhost 9P server");
