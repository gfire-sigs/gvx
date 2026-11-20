/*
 * ABI probe for pkg/sentry/devices/virtgpu. gen.sh compiles this file with
 * clang for each Linux guest target against the libdrm copies of the kernel
 * uAPI headers and reads the constants from the assembly output.
 */
#include <stddef.h>
#include "drm.h"
#include "virtgpu_drm.h"

#define EMIT __attribute__((used)) const unsigned long long
#define CMD(name) EMIT gvx_cmd__##name = (name);
#define NR(name) EMIT gvx_nr__##name = _IOC_NR(name);
#define SIZE(type) EMIT gvx_sizeof__##type = sizeof(struct type);
#define OFF(type, field) EMIT gvx_offsetof__##type##__##field = offsetof(struct type, field);
#define CONST(name) EMIT gvx_const__##name = (name);

/* Requests that the device serves or refuses by name. */
CMD(DRM_IOCTL_VERSION)
CMD(DRM_IOCTL_GET_CAP)
CMD(DRM_IOCTL_GEM_CLOSE)
NR(DRM_IOCTL_PRIME_HANDLE_TO_FD)
NR(DRM_IOCTL_PRIME_FD_TO_HANDLE)
CMD(DRM_IOCTL_VIRTGPU_MAP)
CMD(DRM_IOCTL_VIRTGPU_EXECBUFFER)
CMD(DRM_IOCTL_VIRTGPU_GETPARAM)
NR(DRM_IOCTL_VIRTGPU_RESOURCE_CREATE)
CMD(DRM_IOCTL_VIRTGPU_RESOURCE_INFO)
NR(DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST)
NR(DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST)
NR(DRM_IOCTL_VIRTGPU_WAIT)
CMD(DRM_IOCTL_VIRTGPU_GET_CAPS)
CMD(DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB)
CMD(DRM_IOCTL_VIRTGPU_CONTEXT_INIT)

/* Core request numbers of the refusal table (abi.go, refusedCore). */
NR(DRM_IOCTL_GET_UNIQUE) NR(DRM_IOCTL_GET_MAGIC) NR(DRM_IOCTL_GET_CLIENT) NR(DRM_IOCTL_GET_STATS)
NR(DRM_IOCTL_SET_VERSION) NR(DRM_IOCTL_GEM_FLINK) NR(DRM_IOCTL_GEM_OPEN) NR(DRM_IOCTL_SET_CLIENT_CAP)
NR(DRM_IOCTL_SET_UNIQUE) NR(DRM_IOCTL_AUTH_MAGIC) NR(DRM_IOCTL_BLOCK) NR(DRM_IOCTL_UNBLOCK)
NR(DRM_IOCTL_SET_MASTER) NR(DRM_IOCTL_DROP_MASTER) NR(DRM_IOCTL_ADD_DRAW) NR(DRM_IOCTL_RM_DRAW)
NR(DRM_IOCTL_FINISH) NR(DRM_IOCTL_WAIT_VBLANK) NR(DRM_IOCTL_CRTC_GET_SEQUENCE)
NR(DRM_IOCTL_CRTC_QUEUE_SEQUENCE) NR(DRM_IOCTL_UPDATE_DRAW)
NR(DRM_IOCTL_MODE_GETRESOURCES) NR(DRM_IOCTL_MODE_GETCRTC) NR(DRM_IOCTL_MODE_SETCRTC) NR(DRM_IOCTL_MODE_CURSOR)
NR(DRM_IOCTL_MODE_GETGAMMA) NR(DRM_IOCTL_MODE_SETGAMMA) NR(DRM_IOCTL_MODE_GETENCODER) NR(DRM_IOCTL_MODE_GETCONNECTOR)
NR(DRM_IOCTL_MODE_ATTACHMODE) NR(DRM_IOCTL_MODE_DETACHMODE) NR(DRM_IOCTL_MODE_GETPROPERTY) NR(DRM_IOCTL_MODE_SETPROPERTY)
NR(DRM_IOCTL_MODE_GETPROPBLOB) NR(DRM_IOCTL_MODE_GETFB) NR(DRM_IOCTL_MODE_ADDFB) NR(DRM_IOCTL_MODE_RMFB)
NR(DRM_IOCTL_MODE_PAGE_FLIP) NR(DRM_IOCTL_MODE_DIRTYFB) NR(DRM_IOCTL_MODE_CREATE_DUMB) NR(DRM_IOCTL_MODE_MAP_DUMB)
NR(DRM_IOCTL_MODE_DESTROY_DUMB) NR(DRM_IOCTL_MODE_GETPLANERESOURCES) NR(DRM_IOCTL_MODE_GETPLANE) NR(DRM_IOCTL_MODE_SETPLANE)
NR(DRM_IOCTL_MODE_ADDFB2) NR(DRM_IOCTL_MODE_OBJ_GETPROPERTIES) NR(DRM_IOCTL_MODE_OBJ_SETPROPERTY) NR(DRM_IOCTL_MODE_CURSOR2)
NR(DRM_IOCTL_MODE_ATOMIC) NR(DRM_IOCTL_MODE_CREATEPROPBLOB) NR(DRM_IOCTL_MODE_DESTROYPROPBLOB)
NR(DRM_IOCTL_MODE_CREATE_LEASE) NR(DRM_IOCTL_MODE_LIST_LESSEES) NR(DRM_IOCTL_MODE_GET_LEASE) NR(DRM_IOCTL_MODE_REVOKE_LEASE)
NR(DRM_IOCTL_MODE_GETFB2) NR(DRM_IOCTL_MODE_CLOSEFB)
NR(DRM_IOCTL_SYNCOBJ_CREATE) NR(DRM_IOCTL_SYNCOBJ_DESTROY) NR(DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD) NR(DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE)
NR(DRM_IOCTL_SYNCOBJ_WAIT) NR(DRM_IOCTL_SYNCOBJ_RESET) NR(DRM_IOCTL_SYNCOBJ_SIGNAL)
NR(DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT) NR(DRM_IOCTL_SYNCOBJ_QUERY) NR(DRM_IOCTL_SYNCOBJ_TRANSFER)
NR(DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL) NR(DRM_IOCTL_SYNCOBJ_EVENTFD)

/* Structures that the device copies in or out. */
SIZE(drm_version)
OFF(drm_version, version_major) OFF(drm_version, version_minor) OFF(drm_version, version_patchlevel)
OFF(drm_version, name_len) OFF(drm_version, name) OFF(drm_version, date_len) OFF(drm_version, date)
OFF(drm_version, desc_len) OFF(drm_version, desc)
SIZE(drm_get_cap) OFF(drm_get_cap, capability) OFF(drm_get_cap, value)
SIZE(drm_gem_close) OFF(drm_gem_close, handle) OFF(drm_gem_close, pad)
SIZE(drm_virtgpu_map) OFF(drm_virtgpu_map, offset) OFF(drm_virtgpu_map, handle) OFF(drm_virtgpu_map, pad)
SIZE(drm_virtgpu_execbuffer)
OFF(drm_virtgpu_execbuffer, flags) OFF(drm_virtgpu_execbuffer, size) OFF(drm_virtgpu_execbuffer, command)
OFF(drm_virtgpu_execbuffer, bo_handles) OFF(drm_virtgpu_execbuffer, num_bo_handles) OFF(drm_virtgpu_execbuffer, fence_fd)
OFF(drm_virtgpu_execbuffer, ring_idx) OFF(drm_virtgpu_execbuffer, syncobj_stride) OFF(drm_virtgpu_execbuffer, num_in_syncobjs)
OFF(drm_virtgpu_execbuffer, num_out_syncobjs) OFF(drm_virtgpu_execbuffer, in_syncobjs) OFF(drm_virtgpu_execbuffer, out_syncobjs)
SIZE(drm_virtgpu_getparam) OFF(drm_virtgpu_getparam, param) OFF(drm_virtgpu_getparam, value)
SIZE(drm_virtgpu_resource_info)
OFF(drm_virtgpu_resource_info, bo_handle) OFF(drm_virtgpu_resource_info, res_handle)
OFF(drm_virtgpu_resource_info, size) OFF(drm_virtgpu_resource_info, blob_mem)
SIZE(drm_virtgpu_get_caps)
OFF(drm_virtgpu_get_caps, cap_set_id) OFF(drm_virtgpu_get_caps, cap_set_ver) OFF(drm_virtgpu_get_caps, addr)
OFF(drm_virtgpu_get_caps, size) OFF(drm_virtgpu_get_caps, pad)
SIZE(drm_virtgpu_resource_create_blob)
OFF(drm_virtgpu_resource_create_blob, blob_mem) OFF(drm_virtgpu_resource_create_blob, blob_flags)
OFF(drm_virtgpu_resource_create_blob, bo_handle) OFF(drm_virtgpu_resource_create_blob, res_handle)
OFF(drm_virtgpu_resource_create_blob, size) OFF(drm_virtgpu_resource_create_blob, pad)
OFF(drm_virtgpu_resource_create_blob, cmd_size) OFF(drm_virtgpu_resource_create_blob, cmd)
OFF(drm_virtgpu_resource_create_blob, blob_id)
SIZE(drm_virtgpu_context_set_param) OFF(drm_virtgpu_context_set_param, param) OFF(drm_virtgpu_context_set_param, value)
SIZE(drm_virtgpu_context_init) OFF(drm_virtgpu_context_init, num_params) OFF(drm_virtgpu_context_init, pad)
OFF(drm_virtgpu_context_init, ctx_set_params)

/* Constants. */
CONST(DRM_COMMAND_BASE) CONST(DRM_COMMAND_END)
CONST(DRM_CAP_DUMB_BUFFER) CONST(DRM_CAP_PRIME) CONST(DRM_CAP_TIMESTAMP_MONOTONIC)
CONST(DRM_CAP_SYNCOBJ) CONST(DRM_CAP_SYNCOBJ_TIMELINE)
CONST(VIRTGPU_PARAM_3D_FEATURES) CONST(VIRTGPU_PARAM_CAPSET_QUERY_FIX) CONST(VIRTGPU_PARAM_RESOURCE_BLOB)
CONST(VIRTGPU_PARAM_HOST_VISIBLE) CONST(VIRTGPU_PARAM_CROSS_DEVICE) CONST(VIRTGPU_PARAM_CONTEXT_INIT)
CONST(VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs) CONST(VIRTGPU_PARAM_EXPLICIT_DEBUG_NAME)
CONST(VIRTGPU_EXECBUF_FENCE_FD_IN) CONST(VIRTGPU_EXECBUF_FENCE_FD_OUT) CONST(VIRTGPU_EXECBUF_RING_IDX)
CONST(VIRTGPU_DRM_CAPSET_VENUS)
CONST(VIRTGPU_BLOB_MEM_GUEST) CONST(VIRTGPU_BLOB_MEM_HOST3D) CONST(VIRTGPU_BLOB_MEM_HOST3D_GUEST)
CONST(VIRTGPU_BLOB_FLAG_USE_MAPPABLE) CONST(VIRTGPU_BLOB_FLAG_USE_SHAREABLE) CONST(VIRTGPU_BLOB_FLAG_USE_CROSS_DEVICE)
CONST(VIRTGPU_CONTEXT_PARAM_CAPSET_ID) CONST(VIRTGPU_CONTEXT_PARAM_NUM_RINGS)
CONST(VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK) CONST(VIRTGPU_CONTEXT_PARAM_DEBUG_NAME)
