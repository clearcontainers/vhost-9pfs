/*
 * net/9p/protocol.c
 *
 * 9P Protocol Support Code
 *
 *  Copyright (C) 2008 by Eric Van Hensbergen <ericvh@gmail.com>
 *
 *  Base on code from Anthony Liguori <aliguori@us.ibm.com>
 *  Copyright (C) 2008 by IBM, Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <net/9p/9p.h>

#include "protocol.h"

static size_t pdu_read(struct p9_fcall *pdu, void *data, size_t size)
{
	size_t len = min(pdu->size - pdu->offset, size);
	memcpy(data, &pdu->sdata[pdu->offset], len);
	pdu->offset += len;
	return size - len;
}

static size_t pdu_write(struct p9_fcall *pdu, const void *data, size_t size)
{
	size_t len = min(pdu->capacity - pdu->size, size);
	memcpy(&pdu->sdata[pdu->size], data, len);
	pdu->size += len;
	return size - len;
}

static int p9pdu_vreadf(struct p9_fcall *pdu, const char *fmt, va_list ap)
{
	const char *ptr;
	int errcode = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t *val = va_arg(ap, int8_t *);
				if (pdu_read(pdu, val, sizeof(*val))) {
					errcode = -EFAULT;
					break;
				}
			}
			break;
		case 'w':{
				int16_t *val = va_arg(ap, int16_t *);
				__le16 le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le16_to_cpu(le_val);
			}
			break;
		case 'd':{
				int32_t *val = va_arg(ap, int32_t *);
				__le32 le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le32_to_cpu(le_val);
			}
			break;
		case 'q':{
				int64_t *val = va_arg(ap, int64_t *);
				__le64 le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*val = le64_to_cpu(le_val);
			}
			break;
		case 's':{
				char **sptr = va_arg(ap, char **);
				uint16_t len;

				errcode = p9pdu_readf(pdu, "w", &len);
				if (errcode)
					break;

				*sptr = kmalloc(len + 1, GFP_NOFS);
				if (*sptr == NULL) {
					errcode = -EFAULT;
					break;
				}
				if (pdu_read(pdu, *sptr, len)) {
					errcode = -EFAULT;
					kfree(*sptr);
					*sptr = NULL;
				} else
					(*sptr)[len] = 0;
			}
			break;
		case 'u': {
				kuid_t *uid = va_arg(ap, kuid_t *);
				__le32 le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*uid = make_kuid(&init_user_ns,
						 le32_to_cpu(le_val));
			} break;
		case 'g': {
				kgid_t *gid = va_arg(ap, kgid_t *);
				__le32 le_val;
				if (pdu_read(pdu, &le_val, sizeof(le_val))) {
					errcode = -EFAULT;
					break;
				}
				*gid = make_kgid(&init_user_ns,
						 le32_to_cpu(le_val));
			} break;
		default:
			BUG();
			break;
		}

		if (errcode)
			break;
	}

	return errcode;
}

static int p9pdu_vwritef(struct p9_fcall *pdu, const char *fmt, va_list ap)
{
	const char *ptr;
	int errcode = 0;

	for (ptr = fmt; *ptr; ptr++) {
		switch (*ptr) {
		case 'b':{
				int8_t val = va_arg(ap, int);
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 'w':{
				__le16 val = cpu_to_le16(va_arg(ap, int));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 'd':{
				__le32 val = cpu_to_le32(va_arg(ap, int32_t));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 'q':{
				__le64 val = cpu_to_le64(va_arg(ap, int64_t));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			}
			break;
		case 's':{
				const char *sptr = va_arg(ap, const char *);
				uint16_t len = 0;
				if (sptr)
					len = min_t(size_t, strlen(sptr),
								USHRT_MAX);

				errcode = p9pdu_writef(pdu, "w", len);
				if (!errcode && pdu_write(pdu, sptr, len))
					errcode = -EFAULT;
			}
			break;
		case 'u': {
				kuid_t uid = va_arg(ap, kuid_t);
				__le32 val = cpu_to_le32(
						from_kuid(&init_user_ns, uid));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			} break;
		case 'g': {
				kgid_t gid = va_arg(ap, kgid_t);
				__le32 val = cpu_to_le32(
						from_kgid(&init_user_ns, gid));
				if (pdu_write(pdu, &val, sizeof(val)))
					errcode = -EFAULT;
			} break;
		case 'Q':{
				const struct p9_qid *qid =
				    va_arg(ap, const struct p9_qid *);
				errcode =
				    p9pdu_writef(pdu, "bdq",
						 qid->type, qid->version,
						 qid->path);
			} break;
		default:
			BUG();
			break;
		}

		if (errcode)
			break;
	}

	return errcode;
}

int p9pdu_readf(struct p9_fcall *pdu, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9pdu_vreadf(pdu, fmt, ap);
	va_end(ap);

	return ret;
}

int p9pdu_writef(struct p9_fcall *pdu, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = p9pdu_vwritef(pdu, fmt, ap);
	va_end(ap);

	return ret;
}

int p9pdu_prepare(struct p9_fcall *pdu, int16_t tag, int8_t type)
{
	pdu->id = type;
	pdu->tag = tag;
	return p9pdu_writef(pdu, "dbw", 0, type, tag);
}

int p9pdu_finalize(struct p9_fcall *pdu)
{
	int size = pdu->size;
	int err;

	pdu->size = 0;
	err = p9pdu_writef(pdu, "d", size);
	pdu->size = size;

	return err;
}

void p9pdu_reset(struct p9_fcall *pdu)
{
	pdu->offset = 0;
	pdu->size = 0;
}
