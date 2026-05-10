/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026
 */

#ifndef _SYS_COPE_H
#define	_SYS_COPE_H

#include <sys/ccompile.h>
#include <sys/types.h>
#include <sys/types32.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	COPEIOC		(('c' << 24) | ('o' << 16) | ('p' << 8) | 'e')
#define	COPEIOC_COPE	(COPEIOC | 1)
#define	COPEIOC_MALD	(COPEIOC | 2)

typedef struct cope {
	uint8_t		co_data[8];
	uint32_t	co_id;
} __packed cope_t;

typedef struct cope_ioc {
	cope_t		*ci_copes;
	uint32_t	ci_ncope;
} cope_ioc_t;

typedef struct cope_ioc32 {
	caddr32_t	ci_copes;
	uint32_t	ci_ncope;
} cope_ioc32_t;

#ifdef _KERNEL

#define	COPEMNRN_COPE	0
#define	COPEMNRN_CLONE	1

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_COPE_H */
