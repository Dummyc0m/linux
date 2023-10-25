// SPDX-License-Identifier: GPL-2.0
/*
 * Control guest memory mappings
 *
 * Author: Yuanchu Xie <yuanchu@google.com>
 * Author: Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#define pr_fmt(fmt) "memctl %s: " fmt, __func__

#include <linux/spinlock.h>
#include <linux/io.h>
#include <linux/cpumask.h>
#include <linux/percpu-defs.h>
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/sched/clock.h>
#include <linux/wait.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/resource_ext.h>
#include <linux/memctl.h>
#include <linux/mutex.h>

#define MEMCTL_VERSION "0.01"

#define MEMCTL_CONTROL_PORT (0xbef0)
/* special byte for establishing connection with the host */
#define MEMCTL_CONTROL_BYTE (0xff)

enum memctl_transport_type {
	MEMCTL_TRANSPORT_CONNECT,
	MEMCTL_TRANSPORT_DISCONNECT,
	MEMCTL_TRANSPORT_CONNECT_RESPONSE,
	MEMCTL_TRANSPORT_ACK,
};

struct memctl_transport {
	u64 type;
	union {
		struct {
			u64 nr_cpus;
			u64 buf_phys_addr;
		} request;
		struct {
			u64 port;
			u64 byte;
		} response;
		struct {
			u64 acked_phys_addr;
			u64 _padding;
		} ack;
	};
};

struct memctl_percpu_channel {
	struct memctl_buf buf;
	u64 buf_phys_addr;
	u16 port;
	u8 byte;
};

struct memctl {
	/* cache the info call */
	struct memctl_vmm_info memctl_vmm_info;
	struct memctl_transport transport;
	struct memctl_percpu_channel __percpu *pcpu_channels;
};

static DEFINE_RWLOCK(memctl_lock);
static struct memctl *memctl __read_mostly;

/* kicks host to respond to the write */
static void memctl_write_byte(u16 port_num, u8 byte)
{
	outb(byte, port_num);
}

static void memctl_send_request(struct memctl *memctl, struct memctl_buf *buf)
{
	struct memctl_percpu_channel *channel;

	preempt_disable();
	channel = this_cpu_ptr(memctl->pcpu_channels);
	memcpy(&channel->buf, buf, sizeof(channel->buf));
	memctl_write_byte(channel->port, channel->byte);
	memcpy(buf, &channel->buf, sizeof(*buf));
	preempt_enable();
}

static int __memctl_vmm_call(struct memctl_buf *buf)
{
	int err = 0;
	if (!memctl)
		return -EINVAL;

	read_lock(&memctl_lock);
	if (!memctl) {
		err = -EINVAL;
		goto unlock;
	}
	if (buf->call.func_code == MEMCTL_INFO) {
		memcpy(&buf->info, &memctl->memctl_vmm_info, sizeof(buf->info));
		goto unlock;
	}

	memctl_send_request(memctl, buf);

unlock:
	read_unlock(&memctl_lock);
	return err;
}

/*
 * Used for internal kernel memctl calls, i.e. to better support kernel stacks,
 * or to efficiently zero hugetlb pages.
 */
long memctl_vmm_call(__u64 func_code, __u64 addr, __u64 length, __u64 arg,
		     struct memctl_buf *buf)
{
	buf->call.func_code = func_code;
	buf->call.addr = addr;
	buf->call.length = length;
	buf->call.arg = arg;

	return __memctl_vmm_call(buf);
}
EXPORT_SYMBOL(memctl_vmm_call);

static int memctl_init_info(struct memctl *dev, struct memctl_buf *buf)
{
	buf->call.func_code = MEMCTL_INFO;

	memctl_send_request(dev, buf);
	if (buf->ret.ret_code)
		return buf->ret.ret_code;

	/* Initialize global memctl_vmm_info */
	memcpy(&dev->memctl_vmm_info, &buf->info,
	       sizeof(dev->memctl_vmm_info));
	pr_debug("memctl_vmm_info:\n"
		 "memctl_vmm_info.ret_errno = %u\n"
		 "memctl_vmm_info.ret_code = %u\n"
		 "memctl_vmm_info.big_endian = %llu\n"
		 "memctl_vmm_info.major_version = %u\n"
		 "memctl_vmm_info.minor_version = %u\n"
		 "memctl_vmm_info.page_size = %llu\n",
		 dev->memctl_vmm_info.ret_errno, dev->memctl_vmm_info.ret_code,
		 dev->memctl_vmm_info.big_endian,
		 dev->memctl_vmm_info.major_version,
		 dev->memctl_vmm_info.minor_version,
		 dev->memctl_vmm_info.page_size);

	return 0;
}

static int memctl_open(struct inode *inode, struct file *filp)
{
	struct memctl_buf *buf = NULL;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	/* Do not allow exclusive open */
	if (filp->f_flags & O_EXCL)
		return -EINVAL;

	buf = kzalloc(sizeof(struct memctl_buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Overwrite the misc device set by misc_register */
	filp->private_data = buf;
	return 0;
}

static int memctl_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	filp->private_data = NULL;
	return 0;
}

static long memctl_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long ioctl_param)
{
	struct memctl_buf *buf = filp->private_data;
	int err;

	if (cmd != MEMCTL_IOCTL_VMM)
		return -EINVAL;

	if (copy_from_user(&buf->call, (void __user *)ioctl_param,
			   sizeof(struct memctl_buf)))
		return -EFAULT;

	err = __memctl_vmm_call(buf);
	if (err)
		return err;

	if (copy_to_user((void __user *)ioctl_param, &buf->ret,
			 sizeof(struct memctl_buf)))
		return -EFAULT;

	return 0;
}

static const struct file_operations memctl_fops = {
	.owner = THIS_MODULE,
	.open = memctl_open,
	.release = memctl_release,
	.unlocked_ioctl = memctl_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice memctl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = KBUILD_MODNAME,
	.fops = &memctl_fops,
};

static int memctl_connect(struct memctl *memctl)
{
	struct memctl_transport *transport = &memctl->transport;
	int i, cpu, err = 0;
	u64 transport_phys_addr;

	if (!transport)
		return -ENOMEM;
	transport_phys_addr = virt_to_phys(transport);
	/*
	 * Write the transport physical address in bytes, then
	 * read it back in the buffer to establish the connection.
	 */
	for (i = 0; i < 8; ++i) {
		u8 *ptr = (u8 *)&transport_phys_addr;
		memctl_write_byte(MEMCTL_CONTROL_PORT, ptr[i]);
	}

	if (transport->type != MEMCTL_TRANSPORT_ACK ||
	    transport->ack.acked_phys_addr != transport_phys_addr) {
		pr_err("connect: received %llx expected %llx\n",
		       transport->ack.acked_phys_addr, transport_phys_addr);
		err = -EEXIST;
		goto out;
	}

	for_each_possible_cpu(cpu) {
		struct memctl_percpu_channel *channel =
			per_cpu_ptr(memctl->pcpu_channels, cpu);
		transport->type = MEMCTL_TRANSPORT_CONNECT;
		transport->request.nr_cpus = nr_cpu_ids;
		transport->request.buf_phys_addr = channel->buf_phys_addr;
		memctl_write_byte(MEMCTL_CONTROL_PORT, MEMCTL_CONTROL_BYTE);
		if (transport->type != MEMCTL_TRANSPORT_CONNECT_RESPONSE) {
			pr_err("connect did not receive response\n");
			err = -EINVAL;
			goto out;
		}
		channel->port = transport->response.port;
		channel->byte = transport->response.byte;
	}

out:
	return err;
}

static int memctl_disconnect(struct memctl *memctl)
{
	u64 transport_phys_addr = virt_to_phys(&memctl->transport);

	memset(&memctl->transport, 0, sizeof(memctl->transport));
	memctl->transport.type = MEMCTL_TRANSPORT_DISCONNECT;
	memctl_write_byte(MEMCTL_CONTROL_PORT, MEMCTL_CONTROL_BYTE);
	return memctl->transport.type == MEMCTL_TRANSPORT_ACK &&
	       memctl->transport.ack.acked_phys_addr == transport_phys_addr;
}

static int memctl_alloc_percpu_channels(struct memctl *memctl)
{
	int cpu;

	memctl->pcpu_channels = alloc_percpu_gfp(struct memctl_percpu_channel,
						 GFP_ATOMIC | __GFP_ZERO);
	if (!memctl->pcpu_channels)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct memctl_percpu_channel *channel =
			per_cpu_ptr(memctl->pcpu_channels, cpu);
		phys_addr_t buf_phys = per_cpu_ptr_to_phys(&channel->buf);

		channel->buf_phys_addr = buf_phys;
	}
	return 0;
}

static int __init memctl_init(void)
{
	struct memctl_buf *buf = NULL;
	struct memctl *dev = NULL;
	int err = 0;

	err = misc_register(&memctl_dev);
	if (err)
		return err;

	/* We take a spinlock for a long time, but this is only during init. */
	write_lock(&memctl_lock);
	if (READ_ONCE(memctl)) {
		err = -EEXIST;
		goto fail_free;
	}

	dev = kzalloc(sizeof(struct memctl), GFP_ATOMIC);
	buf = kzalloc(sizeof(struct memctl_buf), GFP_ATOMIC);
	if (!dev || !buf) {
		err = -ENOMEM;
		goto fail_free;
	}

	err = memctl_alloc_percpu_channels(dev);
	if (err)
		goto fail_free;

	err = memctl_connect(dev);
	if (err)
		goto fail_free;

	err = memctl_init_info(dev, buf);
	if (err)
		goto fail_free;

	WRITE_ONCE(memctl, dev);
	write_unlock(&memctl_lock);
	return 0;

fail_free:
	write_unlock(&memctl_lock);
	kfree(dev);
	kfree(buf);
	misc_deregister(&memctl_dev);
	return err;
}

static void __exit memctl_exit(void)
{
	int err;
	struct memctl *dev;

	write_lock(&memctl_lock);
	dev = READ_ONCE(memctl);
	if (!dev) {
		err = -EINVAL;
		pr_err("cleanup called when uninitialized\n");
		write_unlock(&memctl_lock);
		return;
	}

	/* disconnect */
	err = memctl_disconnect(dev);
	if (err)
		pr_err("device did not ack disconnect");
	/* free percpu channels */
	free_percpu(dev->pcpu_channels);

	kfree(dev);
	WRITE_ONCE(memctl, NULL);
	write_unlock(&memctl_lock);
	misc_deregister(&memctl_dev);
}

module_init(memctl_init);
module_exit(memctl_exit);

MODULE_AUTHOR("Yuanchu Xie <yuanchu@google.com>");
MODULE_DESCRIPTION("memctl Guest Service Module");
MODULE_VERSION(MEMCTL_VERSION);
MODULE_LICENSE("GPL");
