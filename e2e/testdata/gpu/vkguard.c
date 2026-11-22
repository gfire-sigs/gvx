// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// vkguard is the guest program of the venus guard gate. Each case sends one
// create info to the host renderer: a valid one that a host driver defect
// made fatal, or an invalid one that the host must refuse. A case must never
// stop the renderer process.
//
// Usage: vkguard list
//        vkguard <case>
//
// A case that sends invalid create info prints "GVX-GUARD case=<case>
// stage=call" immediately before the command that has the invalid create
// info. Each case then prints one line "GVX-GUARD case=<case> result=<result>":
//   ok        each command of a valid case returned VK_SUCCESS
//   refused   the host returned an error for the invalid create info
//   lost      the context stopped after the use of an object that the host
//             refused (the guest driver sends some commands without a reply)
//   accepted  the host accepted the invalid create info
//   fail      a setup command or a command of a valid case failed
// The guest driver can also end the process when the context stops; the
// caller then sees no result line.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>

static const char *case_name;
static VkPhysicalDevice pd;
static VkDevice dev;

static void finish(const char *result, const char *detail, int vk_result) {
	printf("GVX-GUARD case=%s result=%s detail=%s:%d\n", case_name, result, detail, vk_result);
	fflush(stdout);
	exit(0);
}

// stage_call tells the caller that the setup of the case is complete and that
// the next command has the invalid create info.
static void stage_call(void) {
	printf("GVX-GUARD case=%s stage=call\n", case_name);
	fflush(stdout);
}

#define SETUP(call)                                  \
	do {                                         \
		VkResult r_ = (call);                \
		if (r_ != VK_SUCCESS) {              \
			finish("fail", #call, (int)r_); \
		}                                    \
	} while (0)

static void init_device(void) {
	VkApplicationInfo app = {
		.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
		.pApplicationName = "vkguard",
		.apiVersion = VK_API_VERSION_1_1,
	};
	VkInstanceCreateInfo ici = {
		.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
		.pApplicationInfo = &app,
	};
	VkInstance inst;
	SETUP(vkCreateInstance(&ici, NULL, &inst));
	uint32_t n = 1;
	VkResult r = vkEnumeratePhysicalDevices(inst, &n, &pd);
	if ((r != VK_SUCCESS && r != VK_INCOMPLETE) || n != 1) {
		finish("fail", "vkEnumeratePhysicalDevices", (int)r);
	}
	VkPhysicalDeviceProperties props;
	vkGetPhysicalDeviceProperties(pd, &props);
	printf("GVX-GUARD device_name=%s\n", props.deviceName);
	float priority = 1.0f;
	VkDeviceQueueCreateInfo qci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
		.queueCount = 1,
		.pQueuePriorities = &priority,
	};
	VkDeviceCreateInfo dci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
		.queueCreateInfoCount = 1,
		.pQueueCreateInfos = &qci,
	};
	SETUP(vkCreateDevice(pd, &dci, NULL, &dev));
}

static VkImageCreateInfo image_info(VkImageType type, uint32_t w, uint32_t h, uint32_t d,
                                    uint32_t levels, uint32_t layers, VkImageCreateFlags flags) {
	return (VkImageCreateInfo){
		.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
		.flags = flags,
		.imageType = type,
		.format = VK_FORMAT_R8G8B8A8_UNORM,
		.extent = {w, h, d},
		.mipLevels = levels,
		.arrayLayers = layers,
		.samples = VK_SAMPLE_COUNT_1_BIT,
		.tiling = VK_IMAGE_TILING_OPTIMAL,
		.usage = VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT |
		         VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT,
		.sharingMode = VK_SHARING_MODE_EXCLUSIVE,
		.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED,
	};
}

static uint32_t first_memory_type(uint32_t bits) {
	for (uint32_t i = 0; i < 32; i++) {
		if (bits & (1u << i)) {
			return i;
		}
	}
	finish("fail", "no memory type", 0);
	return 0;
}

// bound_image creates a valid image and binds memory to it.
static VkImage bound_image(const VkImageCreateInfo *info) {
	VkImage img;
	SETUP(vkCreateImage(dev, info, NULL, &img));
	VkMemoryRequirements req;
	vkGetImageMemoryRequirements(dev, img, &req);
	VkMemoryAllocateInfo mai = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		.allocationSize = req.size,
		.memoryTypeIndex = first_memory_type(req.memoryTypeBits),
	};
	VkDeviceMemory mem;
	SETUP(vkAllocateMemory(dev, &mai, NULL, &mem));
	SETUP(vkBindImageMemory(dev, img, mem, 0));
	return img;
}

static VkBuffer new_buffer(VkDeviceSize size, VkBufferUsageFlags usage) {
	VkBufferCreateInfo bci = {
		.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
		.size = size,
		.usage = usage,
		.sharingMode = VK_SHARING_MODE_EXCLUSIVE,
	};
	VkBuffer buf;
	SETUP(vkCreateBuffer(dev, &bci, NULL, &buf));
	return buf;
}

static VkBuffer bound_buffer_with_usage(VkDeviceSize size, VkBufferUsageFlags usage) {
	VkBuffer buf = new_buffer(size, usage);
	VkMemoryRequirements req;
	vkGetBufferMemoryRequirements(dev, buf, &req);
	VkMemoryAllocateInfo mai = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		.allocationSize = req.size,
		.memoryTypeIndex = first_memory_type(req.memoryTypeBits),
	};
	VkDeviceMemory mem;
	SETUP(vkAllocateMemory(dev, &mai, NULL, &mem));
	SETUP(vkBindBufferMemory(dev, buf, mem, 0));
	return buf;
}

static VkBuffer bound_buffer(VkDeviceSize size) {
	return bound_buffer_with_usage(size, VK_BUFFER_USAGE_UNIFORM_TEXEL_BUFFER_BIT);
}

// round_trip sends a command that the guest driver cannot answer from a
// cache and waits for the reply of the host. It returns the result.
static VkResult round_trip(void) {
	static uint32_t width = 33;
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_2D, width++, 7, 1, 1, 1, 0);
	VkImage img;
	VkResult r = vkCreateImage(dev, &info, NULL, &img);
	if (r == VK_SUCCESS) {
		vkDestroyImage(dev, img, NULL);
	}
	return r;
}

static VkImageViewCreateInfo view_info(VkImage img, VkImageViewType type, VkFormat format,
                                       uint32_t base_level, uint32_t levels,
                                       uint32_t base_layer, uint32_t layers) {
	return (VkImageViewCreateInfo){
		.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO,
		.image = img,
		.viewType = type,
		.format = format,
		.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, base_level, levels, base_layer, layers},
	};
}

// valid_view creates a view that the host must accept and uses it.
static void valid_view(const VkImageViewCreateInfo *info) {
	VkImageView view;
	SETUP(vkCreateImageView(dev, info, NULL, &view));
	vkDestroyImageView(dev, view, NULL);
	SETUP(round_trip());
}

// refused_image finishes the case with the result of an invalid image.
static void refused_image(const VkImageCreateInfo *info) {
	VkImage img;
	stage_call();
	VkResult r = vkCreateImage(dev, info, NULL, &img);
	if (r != VK_SUCCESS) {
		finish("refused", "vkCreateImage", (int)r);
	}
	finish("accepted", "vkCreateImage", (int)r);
}

// refused_object finishes the case of an invalid view. r is the result of the
// create command, which the guest driver can return before the host saw the
// command. The destroy command made the host look for the object.
static void refused_object(VkResult r, const char *what) {
	if (r != VK_SUCCESS) {
		finish("refused", what, (int)r);
	}
	r = round_trip();
	if (r != VK_SUCCESS) {
		finish("lost", what, (int)r);
	}
	finish("accepted", what, (int)r);
}

static void refused_view(const VkImageViewCreateInfo *info) {
	VkImageView view = VK_NULL_HANDLE;
	stage_call();
	VkResult r = vkCreateImageView(dev, info, NULL, &view);
	if (r == VK_SUCCESS) {
		vkDestroyImageView(dev, view, NULL);
	}
	refused_object(r, "vkCreateImageView");
}

static void refused_buffer_view_at(VkBuffer buf, VkFormat format, VkDeviceSize offset, VkDeviceSize range) {
	VkBufferViewCreateInfo info = {
		.sType = VK_STRUCTURE_TYPE_BUFFER_VIEW_CREATE_INFO,
		.buffer = buf,
		.format = format,
		.offset = offset,
		.range = range,
	};
	VkBufferView view = VK_NULL_HANDLE;
	stage_call();
	VkResult r = vkCreateBufferView(dev, &info, NULL, &view);
	if (r == VK_SUCCESS) {
		vkDestroyBufferView(dev, view, NULL);
	}
	refused_object(r, "vkCreateBufferView");
}

static void refused_buffer_view(VkBuffer buf, VkFormat format, VkDeviceSize range) {
	refused_buffer_view_at(buf, format, 0, range);
}

// A valid image that stopped the host driver: ANGLE makes it for
// texStorage3D(TEXTURE_3D, 4, RGBA8, 1, 1, 8).
static VkImageCreateInfo image_3d_1x1x8(void) {
	return image_info(VK_IMAGE_TYPE_3D, 1, 1, 8, 4, 1, VK_IMAGE_CREATE_2D_ARRAY_COMPATIBLE_BIT);
}

static void case_valid_3d_1x1x8(void) {
	VkImage img = bound_image(&(VkImageCreateInfo[]){image_3d_1x1x8()}[0]);
	valid_view(&(VkImageViewCreateInfo[]){
		view_info(img, VK_IMAGE_VIEW_TYPE_3D, VK_FORMAT_R8G8B8A8_UNORM, 0, 4, 0, 1)}[0]);
	finish("ok", "3D view", 0);
}

static void case_valid_3d_2x2x8(void) {
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_3D, 2, 2, 8, 3, 1, VK_IMAGE_CREATE_2D_ARRAY_COMPATIBLE_BIT);
	VkImage img = bound_image(&info);
	valid_view(&(VkImageViewCreateInfo[]){
		view_info(img, VK_IMAGE_VIEW_TYPE_3D, VK_FORMAT_R8G8B8A8_UNORM, 0, 3, 0, 1)}[0]);
	finish("ok", "3D view", 0);
}

// The last case: the objects of an ordinary application still work.
static void case_alive(void) {
	VkImageCreateInfo info3d = image_info(VK_IMAGE_TYPE_3D, 8, 8, 8, 4, 1, VK_IMAGE_CREATE_2D_ARRAY_COMPATIBLE_BIT);
	VkImage img3d = bound_image(&info3d);
	valid_view(&(VkImageViewCreateInfo[]){
		view_info(img3d, VK_IMAGE_VIEW_TYPE_3D, VK_FORMAT_R8G8B8A8_UNORM, 0, 4, 0, 1)}[0]);
	valid_view(&(VkImageViewCreateInfo[]){
		view_info(img3d, VK_IMAGE_VIEW_TYPE_2D_ARRAY, VK_FORMAT_R8G8B8A8_UNORM, 0, 1, 0, 8)}[0]);
	valid_view(&(VkImageViewCreateInfo[]){
		view_info(img3d, VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, 1, 1, 3, 1)}[0]);

	VkImageCreateInfo cube = image_info(VK_IMAGE_TYPE_2D, 16, 16, 1, 5, 6,
	                                    VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT | VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT);
	VkImage imgcube = bound_image(&cube);
	valid_view(&(VkImageViewCreateInfo[]){
		view_info(imgcube, VK_IMAGE_VIEW_TYPE_CUBE, VK_FORMAT_R8G8B8A8_SRGB, 0, VK_REMAINING_MIP_LEVELS, 0,
		          VK_REMAINING_ARRAY_LAYERS)}[0]);
	valid_view(&(VkImageViewCreateInfo[]){
		view_info(imgcube, VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, 4, 1, 5, 1)}[0]);

	VkBufferViewCreateInfo bvi = {
		.sType = VK_STRUCTURE_TYPE_BUFFER_VIEW_CREATE_INFO,
		.buffer = bound_buffer(4096),
		.format = VK_FORMAT_R8G8B8A8_UNORM,
		.offset = 16,
		.range = VK_WHOLE_SIZE,
	};
	VkBufferView bview;
	SETUP(vkCreateBufferView(dev, &bvi, NULL, &bview));
	vkDestroyBufferView(dev, bview, NULL);
	SETUP(round_trip());
	finish("ok", "views", 0);
}

static void case_image_levels(void) {
	refused_image(&(VkImageCreateInfo[]){image_info(VK_IMAGE_TYPE_2D, 8, 8, 1, 5, 1, 0)}[0]);
}

static void case_image_zero_extent(void) {
	refused_image(&(VkImageCreateInfo[]){image_info(VK_IMAGE_TYPE_2D, 0, 8, 1, 1, 1, 0)}[0]);
}

static void case_image_extent(void) {
	refused_image(&(VkImageCreateInfo[]){image_info(VK_IMAGE_TYPE_2D, 1000000, 8, 1, 1, 1, 0)}[0]);
}

static void case_image_layers(void) {
	refused_image(&(VkImageCreateInfo[]){image_info(VK_IMAGE_TYPE_2D, 8, 8, 1, 1, 100000, 0)}[0]);
}

static void case_image_type(void) {
	refused_image(&(VkImageCreateInfo[]){image_info((VkImageType)7, 8, 8, 1, 1, 1, 0)}[0]);
}

static void case_image_samples(void) {
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_2D, 8, 8, 1, 1, 1, 0);
	info.samples = (VkSampleCountFlagBits)3;
	refused_image(&info);
}

static void case_image_format(void) {
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_2D, 8, 8, 1, 1, 1, 0);
	info.format = VK_FORMAT_R8G8B8A8_USCALED;
	refused_image(&info);
}

static void case_image_cube(void) {
	refused_image(&(VkImageCreateInfo[]){
		image_info(VK_IMAGE_TYPE_2D, 8, 4, 1, 1, 6, VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT)}[0]);
}

static VkImage image_2d_array(VkImageCreateFlags flags) {
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_2D, 16, 16, 1, 3, 6, flags);
	return bound_image(&info);
}

static void case_view_levels(void) {
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(image_2d_array(0), VK_IMAGE_VIEW_TYPE_2D_ARRAY, VK_FORMAT_R8G8B8A8_UNORM, 0, 5, 0, 6)}[0]);
}

static void case_view_layers(void) {
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(image_2d_array(0), VK_IMAGE_VIEW_TYPE_2D_ARRAY, VK_FORMAT_R8G8B8A8_UNORM, 0, 3, 4, 6)}[0]);
}

static void case_view_layer_count(void) {
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(image_2d_array(0), VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, 0, 3, 0, 6)}[0]);
}

static void case_view_type(void) {
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(image_2d_array(0), VK_IMAGE_VIEW_TYPE_3D, VK_FORMAT_R8G8B8A8_UNORM, 0, 3, 0, 1)}[0]);
}

static void case_view_cube(void) {
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(image_2d_array(VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT), VK_IMAGE_VIEW_TYPE_CUBE,
		          VK_FORMAT_R8G8B8A8_UNORM, 0, 3, 0, 5)}[0]);
}

static void case_view_format(void) {
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(image_2d_array(VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT), VK_IMAGE_VIEW_TYPE_2D_ARRAY,
		          VK_FORMAT_R32G32B32A32_SFLOAT, 0, 3, 0, 6)}[0]);
}

static void case_view_aspects(void) {
	VkImageViewCreateInfo info =
		view_info(image_2d_array(0), VK_IMAGE_VIEW_TYPE_2D_ARRAY, VK_FORMAT_R8G8B8A8_UNORM, 0, 3, 0, 6);
	info.subresourceRange.aspectMask = 0x7fffffff;
	refused_view(&info);
}

static void case_view_swizzle(void) {
	VkImageViewCreateInfo info =
		view_info(image_2d_array(0), VK_IMAGE_VIEW_TYPE_2D_ARRAY, VK_FORMAT_R8G8B8A8_UNORM, 0, 3, 0, 6);
	info.components.g = (VkComponentSwizzle)1000;
	refused_view(&info);
}

// The host removes the 2D view support of this image, so it must refuse the
// 2D array view: the host driver has no texture for it.
static void case_view_2d_of_3d_1x1x8(void) {
	VkImage img = bound_image(&(VkImageCreateInfo[]){image_3d_1x1x8()}[0]);
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(img, VK_IMAGE_VIEW_TYPE_2D_ARRAY, VK_FORMAT_R8G8B8A8_UNORM, 0, 1, 0, 8)}[0]);
}

static void case_buffer_view_elements(void) {
	refused_buffer_view(bound_buffer(4096), VK_FORMAT_R8G8B8A8_UNORM, 2);
}

static void case_buffer_view_range(void) {
	refused_buffer_view(bound_buffer(4096), VK_FORMAT_R8G8B8A8_UNORM, 1u << 20);
}

static void case_buffer_view_format(void) {
	refused_buffer_view(bound_buffer(4096), VK_FORMAT_D32_SFLOAT, 4096);
}

static void case_buffer_view_scaled_format(void) {
	refused_buffer_view(bound_buffer(4096), VK_FORMAT_R8G8B8A8_USCALED, 4096);
}

// A 2-plane 4:2:0 image (NV12). Each chroma plane has one half of the width
// and of the height, so an odd extent gives the host a plane of size 0.
static VkImageCreateInfo image_2plane_420(uint32_t w, uint32_t h, VkImageCreateFlags flags) {
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_2D, w, h, 1, 1, 1, flags);
	info.format = VK_FORMAT_G8_B8R8_2PLANE_420_UNORM;
	info.usage = VK_IMAGE_USAGE_SAMPLED_BIT;
	return info;
}

static void case_valid_2plane_420(void) {
	VkImageCreateInfo info = image_2plane_420(8, 8, VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT);
	VkImage img = bound_image(&info);
	VkImageViewCreateInfo view = view_info(img, VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8_UNORM, 0, 1, 0, 1);
	view.subresourceRange.aspectMask = VK_IMAGE_ASPECT_PLANE_1_BIT;
	valid_view(&view);
	finish("ok", "plane view", 0);
}

static void case_image_420_odd_extent(void) {
	refused_image(&(VkImageCreateInfo[]){image_2plane_420(1, 1, 0)}[0]);
}

// A view of one plane needs the mutable format flag on the image.
static void case_view_plane_not_mutable(void) {
	VkImageCreateInfo info = image_2plane_420(8, 8, 0);
	VkImageViewCreateInfo view =
		view_info(bound_image(&info), VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8_UNORM, 0, 1, 0, 1);
	view.subresourceRange.aspectMask = VK_IMAGE_ASPECT_PLANE_0_BIT;
	refused_view(&view);
}

// A 2-plane image has no plane 2.
static void case_view_plane_index(void) {
	VkImageCreateInfo info = image_2plane_420(8, 8, VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT);
	VkImageViewCreateInfo view =
		view_info(bound_image(&info), VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8_UNORM, 0, 1, 0, 1);
	view.subresourceRange.aspectMask = VK_IMAGE_ASPECT_PLANE_2_BIT;
	refused_view(&view);
}

// The format of plane 0 is R8, and a 32-bit format is not in its class.
static void case_view_plane_format(void) {
	VkImageCreateInfo info = image_2plane_420(8, 8, VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT);
	VkImageViewCreateInfo view =
		view_info(bound_image(&info), VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, 0, 1, 0, 1);
	view.subresourceRange.aspectMask = VK_IMAGE_ASPECT_PLANE_0_BIT;
	refused_view(&view);
}

// The image has no memory.
static void case_view_unbound(void) {
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_2D, 16, 16, 1, 1, 1, 0);
	VkImage img;
	SETUP(vkCreateImage(dev, &info, NULL, &img));
	refused_view(&(VkImageViewCreateInfo[]){
		view_info(img, VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, 0, 1, 0, 1)}[0]);
}

// The view asks for storage usage, and the image has only sampled usage.
static void case_view_usage(void) {
	VkImageCreateInfo info = image_info(VK_IMAGE_TYPE_2D, 16, 16, 1, 1, 1, 0);
	info.usage = VK_IMAGE_USAGE_SAMPLED_BIT;
	VkImageViewUsageCreateInfo usage = {
		.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_USAGE_CREATE_INFO,
		.usage = VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_STORAGE_BIT,
	};
	VkImageViewCreateInfo view =
		view_info(bound_image(&info), VK_IMAGE_VIEW_TYPE_2D, VK_FORMAT_R8G8B8A8_UNORM, 0, 1, 0, 1);
	view.pNext = &usage;
	refused_view(&view);
}

static void case_buffer_view_unbound(void) {
	refused_buffer_view(new_buffer(4096, VK_BUFFER_USAGE_UNIFORM_TEXEL_BUFFER_BIT), VK_FORMAT_R8G8B8A8_UNORM, 4096);
}

// The offset is not a multiple of a texel or of the alignment of the device.
static void case_buffer_view_offset(void) {
	refused_buffer_view_at(bound_buffer(4096), VK_FORMAT_R8G8B8A8_UNORM, 2, 1024);
}

// The buffer has no texel buffer usage.
static void case_buffer_view_usage(void) {
	refused_buffer_view(bound_buffer_with_usage(4096, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT), VK_FORMAT_R8G8B8A8_UNORM, 4096);
}

static const struct {
	const char *name;
	void (*run)(void);
} cases[] = {
	{"valid-3d-1x1x8", case_valid_3d_1x1x8},
	{"valid-3d-2x2x8", case_valid_3d_2x2x8},
	{"valid-2plane-420", case_valid_2plane_420},
	{"image-levels", case_image_levels},
	{"image-zero-extent", case_image_zero_extent},
	{"image-extent", case_image_extent},
	{"image-layers", case_image_layers},
	{"image-type", case_image_type},
	{"image-samples", case_image_samples},
	{"image-format", case_image_format},
	{"image-cube", case_image_cube},
	{"image-420-odd-extent", case_image_420_odd_extent},
	{"view-levels", case_view_levels},
	{"view-layers", case_view_layers},
	{"view-layer-count", case_view_layer_count},
	{"view-type", case_view_type},
	{"view-cube", case_view_cube},
	{"view-format", case_view_format},
	{"view-aspects", case_view_aspects},
	{"view-swizzle", case_view_swizzle},
	{"view-2d-of-3d-1x1x8", case_view_2d_of_3d_1x1x8},
	{"view-plane-not-mutable", case_view_plane_not_mutable},
	{"view-plane-index", case_view_plane_index},
	{"view-plane-format", case_view_plane_format},
	{"view-unbound", case_view_unbound},
	{"view-usage", case_view_usage},
	{"buffer-view-elements", case_buffer_view_elements},
	{"buffer-view-range", case_buffer_view_range},
	{"buffer-view-format", case_buffer_view_format},
	{"buffer-view-scaled-format", case_buffer_view_scaled_format},
	{"buffer-view-unbound", case_buffer_view_unbound},
	{"buffer-view-offset", case_buffer_view_offset},
	{"buffer-view-usage", case_buffer_view_usage},
	{"alive", case_alive},
};

int main(int argc, char **argv) {
	const size_t n = sizeof(cases) / sizeof(cases[0]);
	if (argc != 2) {
		fprintf(stderr, "usage: vkguard list | vkguard <case>\n");
		return 2;
	}
	if (strcmp(argv[1], "list") == 0) {
		for (size_t i = 0; i < n; i++) {
			printf("%s\n", cases[i].name);
		}
		return 0;
	}
	for (size_t i = 0; i < n; i++) {
		if (strcmp(argv[1], cases[i].name) == 0) {
			case_name = cases[i].name;
			init_device();
			cases[i].run();
			finish("fail", "the case did not finish", 0);
		}
	}
	fprintf(stderr, "vkguard: unknown case %s\n", argv[1]);
	return 2;
}
