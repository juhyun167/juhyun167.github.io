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
 * Copyright 2026 Cringe CTFers Incorporated
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cope.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/list.h>
#include <sys/proc.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/vmem.h>

#define	COPE_BATCH_MAX	30

typedef struct cope_bufhdr {
	uint64_t	cbh_cookie;
	uint32_t	cbh_pad;
} __packed cope_bufhdr_t;

typedef struct cope_state {
	list_node_t	cps_node;
	kmutex_t	cps_lock;
	kcondvar_t	cps_cv;
	boolean_t	cps_busy;
	boolean_t	cps_closing;
	uint_t		cps_refs;
	proc_t		*cps_proc;
	uint64_t	cps_cookie;
	cope_t		*cps_buf;
	size_t		cps_alloc;
} cope_state_t;

typedef struct cope_softc {
	cope_state_t	*csc_state;
} cope_softc_t;

static kmutex_t		cope_lock;
static kmem_cache_t	*cope_state_cache;
static dev_info_t	*cope_devi;
static vmem_t		*cope_minor;
static list_t		cope_state_list;
static void		*cope_softstate;
static uint32_t		cope_next_id = 1;

CTASSERT(sizeof (cope_t) == 12);
CTASSERT(sizeof (cope_bufhdr_t) == sizeof (cope_t));

static int cope_open(dev_t *, int, int, cred_t *);
static int cope_close(dev_t, int, int, cred_t *);
static int cope_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int cope_attach(dev_info_t *, ddi_attach_cmd_t);
static int cope_detach(dev_info_t *, ddi_detach_cmd_t);
static int cope_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static cope_state_t *
cope_state_lookup_proc(proc_t *proc)
{
	cope_state_t *state;

	ASSERT(MUTEX_HELD(&cope_lock));

	for (state = list_head(&cope_state_list); state != NULL;
	    state = list_next(&cope_state_list, state)) {
		if (state->cps_proc == proc)
			return (state);
	}

	return (NULL);
}

static void
cope_cookie_fill(uint64_t *cookiep)
{
	if (random_get_bytes((uint8_t *)cookiep, sizeof (*cookiep)) != 0)
		VERIFY0(random_get_pseudo_bytes((uint8_t *)cookiep,
		    sizeof (*cookiep)));
}

static cope_bufhdr_t *
cope_bufhdr(cope_t *buf)
{
	return ((cope_bufhdr_t *)((uintptr_t)buf - sizeof (cope_bufhdr_t)));
}

static void
cope_state_hold(cope_state_t *state)
{
	mutex_enter(&state->cps_lock);
	state->cps_refs++;
	mutex_exit(&state->cps_lock);
}

static cope_state_t *
cope_state_hold_by_minor(minor_t minor)
{
	cope_softc_t *softc;
	cope_state_t *state = NULL;

	mutex_enter(&cope_lock);
	softc = ddi_get_soft_state(cope_softstate, minor);
	if (softc != NULL) {
		state = softc->csc_state;
		if (state != NULL)
			cope_state_hold(state);
	}
	mutex_exit(&cope_lock);

	return (state);
}

static void
cope_state_rele(cope_state_t *state)
{
	mutex_enter(&state->cps_lock);
	ASSERT3U(state->cps_refs, >, 0);
	state->cps_refs--;
	cv_broadcast(&state->cps_cv);
	mutex_exit(&state->cps_lock);
}

static void
cope_buf_free(cope_t *buf, size_t alloc)
{
	cope_bufhdr_t *hdr;
	size_t sz;

	if (buf == NULL)
		return;

	hdr = cope_bufhdr(buf);
	sz = sizeof (*hdr) + alloc;
	bzero(hdr, sz);
	kmem_free(hdr, sz);
}

static int
cope_state_enter(cope_state_t *state)
{
	mutex_enter(&state->cps_lock);
	while (state->cps_busy && !state->cps_closing)
		cv_wait(&state->cps_cv, &state->cps_lock);
	if (state->cps_closing) {
		mutex_exit(&state->cps_lock);
		return (ENXIO);
	}
	state->cps_busy = B_TRUE;
	mutex_exit(&state->cps_lock);

	return (0);
}

static void
cope_state_exit(cope_state_t *state)
{
	mutex_enter(&state->cps_lock);
	state->cps_busy = B_FALSE;
	cv_broadcast(&state->cps_cv);
	mutex_exit(&state->cps_lock);
}

static int
cope_state_cookie_check(cope_state_t *state)
{
	if (state->cps_buf == NULL)
		return (EIO);

	if (cope_bufhdr(state->cps_buf)->cbh_cookie != state->cps_cookie)
		return (EIO);

	return (0);
}

static int
cope_copyin_ioc(intptr_t arg, int md, cope_ioc_t *ioc)
{
	if (ddi_model_convert_from(md) == DDI_MODEL_ILP32) {
		cope_ioc32_t ioc32;

		if (ddi_copyin((void *)arg, &ioc32, sizeof (ioc32), md) != 0)
			return (EFAULT);

		ioc->ci_copes = (cope_t *)(uintptr_t)ioc32.ci_copes;
		ioc->ci_ncope = ioc32.ci_ncope;
	} else {
		if (ddi_copyin((void *)arg, ioc, sizeof (*ioc), md) != 0)
			return (EFAULT);
	}

	return (0);
}

static int
cope_ensure_buf(cope_state_t *state, size_t want)
{
	cope_bufhdr_t *oldhdr, *newhdr;
	uint64_t cookie;
	size_t oldsz;

	if (state->cps_buf != NULL && want <= state->cps_alloc)
		return (0);

	want = MAX(want, (size_t)1);
	cope_cookie_fill(&cookie);
	newhdr = kmem_alloc(sizeof (*newhdr) + want, KM_SLEEP);
	newhdr->cbh_cookie = cookie;
	newhdr->cbh_pad = 0;

	oldhdr = state->cps_buf == NULL ? NULL : cope_bufhdr(state->cps_buf);
	oldsz = state->cps_alloc;
	state->cps_cookie = cookie;
	state->cps_buf = (cope_t *)(newhdr + 1);
	state->cps_alloc = want;

	if (oldhdr != NULL)
		cope_buf_free((cope_t *)(oldhdr + 1), oldsz);

	return (0);
}

static int
cope_do_cope(cope_state_t *state, intptr_t arg, int md)
{
	cope_ioc_t ioc;
	uint32_t allocsz;
	uint32_t ncopy;
	size_t copysz;
	uint32_t i;
	int err;

	if ((err = cope_copyin_ioc(arg, md, &ioc)) != 0)
		return (err);

	if (ioc.ci_ncope == 0)
		return (0);

	allocsz = ioc.ci_ncope * sizeof (cope_t);
	ncopy = MIN(ioc.ci_ncope, (uint32_t)COPE_BATCH_MAX);
	copysz = (size_t)ncopy * sizeof (cope_t);

	err = cope_ensure_buf(state, allocsz);
	if (err != 0)
		goto out;

	if (ddi_copyin(ioc.ci_copes, state->cps_buf, copysz, md) != 0) {
		err = EFAULT;
		goto out;
	}

	for (i = 0; i < ncopy; i++)
		state->cps_buf[i].co_id = cope_next_id++;

	if (ddi_copyout(state->cps_buf, ioc.ci_copes, copysz, md) != 0) {
		err = EFAULT;
		goto out;
	}

	err = 0;

out:
	return (err);
}

static int
cope_do_mald(intptr_t arg, int md)
{
	uint32_t latest;

	latest = cope_next_id - 1;
	if (ddi_copyout(&latest, (void *)arg, sizeof (latest), md) != 0)
		return (EFAULT);

	return (0);
}

static int
cope_open(dev_t *devp, int flag __unused, int otyp __unused,
    cred_t *cr __unused)
{
	cope_softc_t *softc;
	cope_state_t *state;
	major_t major = getemajor(*devp);
	minor_t minor = getminor(*devp);

	if (minor != COPEMNRN_COPE)
		return (ENXIO);

	mutex_enter(&cope_lock);

	if (cope_state_lookup_proc(curproc) != NULL) {
		mutex_exit(&cope_lock);
		return (EBUSY);
	}

	minor = (minor_t)(uintptr_t)vmem_alloc(cope_minor, 1,
	    VM_BESTFIT | VM_SLEEP);

	if (ddi_soft_state_zalloc(cope_softstate, minor) != DDI_SUCCESS) {
		vmem_free(cope_minor, (void *)(uintptr_t)minor, 1);
		mutex_exit(&cope_lock);
		return (ENXIO);
	}

	softc = ddi_get_soft_state(cope_softstate, minor);
	state = kmem_cache_alloc(cope_state_cache, KM_SLEEP);
	bzero(state, sizeof (*state));
	softc->csc_state = state;
	*devp = makedevice(major, minor);

	state->cps_proc = curproc;
	state->cps_refs = 1;
	mutex_init(&state->cps_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&state->cps_cv, NULL, CV_DEFAULT, NULL);
	(void) cope_ensure_buf(state, 1);
	list_insert_tail(&cope_state_list, state);

	mutex_exit(&cope_lock);

	return (0);
}

static int
cope_close(dev_t dev, int flag __unused, int otyp __unused, cred_t *cr __unused)
{
	cope_softc_t *softc;
	cope_state_t *state;
	minor_t minor = getminor(dev);

	mutex_enter(&cope_lock);
	softc = ddi_get_soft_state(cope_softstate, minor);
	if (softc == NULL || (state = softc->csc_state) == NULL) {
		mutex_exit(&cope_lock);
		return (ENXIO);
	}
	softc->csc_state = NULL;
	mutex_exit(&cope_lock);

	mutex_enter(&state->cps_lock);
	state->cps_closing = B_TRUE;
	while (state->cps_busy || state->cps_refs > 1)
		cv_wait(&state->cps_cv, &state->cps_lock);
	ASSERT3U(state->cps_refs, ==, 1);
	state->cps_refs = 0;
	mutex_exit(&state->cps_lock);

	mutex_enter(&cope_lock);
	list_remove(&cope_state_list, state);
	mutex_exit(&cope_lock);

	cope_buf_free(state->cps_buf, state->cps_alloc);

	mutex_destroy(&state->cps_lock);
	cv_destroy(&state->cps_cv);
	bzero(state, sizeof (*state));
	kmem_cache_free(cope_state_cache, state);
	ddi_soft_state_free(cope_softstate, minor);
	vmem_free(cope_minor, (void *)(uintptr_t)minor, 1);

	return (0);
}

static int
cope_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr __unused,
    int *rv __unused)
{
	cope_state_t *state;
	int err;

	state = cope_state_hold_by_minor(getminor(dev));
	if (state == NULL)
		return (ENXIO);

	if ((err = cope_state_enter(state)) != 0)
		goto out;

	if ((err = cope_state_cookie_check(state)) != 0)
		goto out_exit;

	switch (cmd) {
	case COPEIOC_COPE:
		err = cope_do_cope(state, arg, md);
		break;
	case COPEIOC_MALD:
		err = cope_do_mald(arg, md);
		break;
	default:
		err = ENOTTY;
		break;
	}

out_exit:
	cope_state_exit(state);
out:
	cope_state_rele(state);
	return (err);
}

static int
cope_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&cope_lock);

	if (ddi_soft_state_init(&cope_softstate, sizeof (cope_softc_t), 0) !=
	    0) {
		cmn_err(CE_NOTE, "/dev/cope failed to create soft state");
		mutex_exit(&cope_lock);
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "cope", S_IFCHR, COPEMNRN_COPE,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		cmn_err(CE_NOTE, "/dev/cope couldn't create minor node");
		ddi_soft_state_fini(&cope_softstate);
		mutex_exit(&cope_lock);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	cope_devi = devi;

	cope_minor = vmem_create("cope_minor", (void *)COPEMNRN_CLONE,
	    UINT32_MAX - COPEMNRN_CLONE, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	mutex_exit(&cope_lock);

	return (DDI_SUCCESS);
}

static int
cope_detach(dev_info_t *dip __unused, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&cope_lock);
	vmem_destroy(cope_minor);

	ddi_remove_minor_node(cope_devi, NULL);
	cope_devi = NULL;

	ddi_soft_state_fini(&cope_softstate);
	mutex_exit(&cope_lock);

	return (DDI_SUCCESS);
}

static int
cope_info(dev_info_t *dip __unused, ddi_info_cmd_t infocmd, void *arg __unused,
    void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)cope_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}

	return (error);
}

static struct cb_ops cope_cb_ops = {
	cope_open,		/* open */
	cope_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	cope_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab */
	D_NEW | D_MP		/* compatibility flags */
};

static struct dev_ops cope_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	cope_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	cope_attach,		/* attach */
	cope_detach,		/* detach */
	nodev,			/* reset */
	&cope_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"cope support",		/* name of module */
	&cope_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int ret;

	mutex_init(&cope_lock, NULL, MUTEX_DEFAULT, NULL);
	cope_state_cache = kmem_cache_create("cope_state_cache",
	    sizeof (cope_state_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	list_create(&cope_state_list, sizeof (cope_state_t),
	    offsetof(cope_state_t, cps_node));
	ret = mod_install(&modlinkage);
	if (ret != 0) {
		kmem_cache_destroy(cope_state_cache);
		list_destroy(&cope_state_list);
		mutex_destroy(&cope_lock);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&modlinkage);
	if (ret == 0) {
		kmem_cache_destroy(cope_state_cache);
		list_destroy(&cope_state_list);
		mutex_destroy(&cope_lock);
	}

	return (ret);
}
