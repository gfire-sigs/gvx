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

// vkcompute is the guest Vulkan compute probe of gate G1. It selects a
// Vulkan device, fills a host-visible source buffer from the CPU, runs
// vkcompute.comp on the device, and reads the destination buffer back
// through vkMapMemory. On venus, host-visible memory is a blob that the
// guest maps through DRM_IOCTL_VIRTGPU_MAP and mmap of the render node, and
// each submission goes through the venus ring and DRM_IOCTL_VIRTGPU_EXECBUFFER.
//
// Usage: vkcompute <shader.spv>
// Environment:
//   GVX_VK_DEVICE   substring that the device name must contain (default: none)
//   GVX_VK_WORDS    number of 32-bit words, a multiple of 256 (default 1048576)
//   GVX_VK_ROUNDS   timed submit-and-wait rounds (default 50)
//
// Each result line has the form "GVX-VK key=value". The last line is
// "GVX-VK done". The exit code is 0 only when every check passed.

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

#define LOCAL_SIZE 256u
#define FENCE_TIMEOUT_NS (10ull * 1000 * 1000 * 1000)

static int failures;

#define CHECK(call)                                                          \
	do {                                                                 \
		VkResult r_ = (call);                                        \
		if (r_ != VK_SUCCESS) {                                      \
			printf("GVX-VK error=%s:%d %s returned %d\n", __FILE__, \
			       __LINE__, #call, (int)r_);                    \
			printf("GVX-VK result=FAIL\nGVX-VK done\n");         \
			exit(1);                                             \
		}                                                            \
	} while (0)

static double now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static uint32_t env_u32(const char *name, uint32_t def) {
	const char *v = getenv(name);
	if (v == NULL || *v == '\0') {
		return def;
	}
	return (uint32_t)strtoul(v, NULL, 0);
}

static uint32_t expected_word(uint32_t i, uint32_t src) {
	return (src * 3u + i) ^ 0xA5A5A5A5u;
}

static uint32_t source_word(uint32_t i) {
	return i * 0x01000193u;
}

static void *read_file(const char *path, size_t *size) {
	FILE *f = fopen(path, "rb");
	if (f == NULL) {
		printf("GVX-VK error=open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fseek(f, 0, SEEK_SET);
	void *buf = malloc((size_t)n);
	if (buf == NULL || fread(buf, 1, (size_t)n, f) != (size_t)n) {
		fclose(f);
		free(buf);
		printf("GVX-VK error=read %s\n", path);
		return NULL;
	}
	fclose(f);
	*size = (size_t)n;
	return buf;
}

static int has_extension(VkPhysicalDevice pd, const char *name) {
	uint32_t n = 0;
	vkEnumerateDeviceExtensionProperties(pd, NULL, &n, NULL);
	VkExtensionProperties *ext = calloc(n, sizeof(*ext));
	vkEnumerateDeviceExtensionProperties(pd, NULL, &n, ext);
	int found = 0;
	for (uint32_t i = 0; i < n; i++) {
		if (strcmp(ext[i].extensionName, name) == 0) {
			found = 1;
		}
	}
	free(ext);
	return found;
}

static uint32_t find_memory_type(VkPhysicalDevice pd, uint32_t bits, VkMemoryPropertyFlags want) {
	VkPhysicalDeviceMemoryProperties mp;
	vkGetPhysicalDeviceMemoryProperties(pd, &mp);
	for (uint32_t i = 0; i < mp.memoryTypeCount; i++) {
		if ((bits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & want) == want) {
			return i;
		}
	}
	return UINT32_MAX;
}

struct buffer {
	VkBuffer buf;
	VkDeviceMemory mem;
	uint32_t *map;
};

static void create_buffer(VkPhysicalDevice pd, VkDevice dev, VkDeviceSize size, struct buffer *b) {
	VkBufferCreateInfo bci = {
		.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
		.size = size,
		.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
		.sharingMode = VK_SHARING_MODE_EXCLUSIVE,
	};
	CHECK(vkCreateBuffer(dev, &bci, NULL, &b->buf));
	VkMemoryRequirements req;
	vkGetBufferMemoryRequirements(dev, b->buf, &req);
	uint32_t type = find_memory_type(pd, req.memoryTypeBits,
	                                 VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
	if (type == UINT32_MAX) {
		printf("GVX-VK error=no host-visible coherent memory type\nGVX-VK result=FAIL\nGVX-VK done\n");
		exit(1);
	}
	VkMemoryAllocateInfo mai = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		.allocationSize = req.size,
		.memoryTypeIndex = type,
	};
	CHECK(vkAllocateMemory(dev, &mai, NULL, &b->mem));
	CHECK(vkBindBufferMemory(dev, b->buf, b->mem, 0));
	CHECK(vkMapMemory(dev, b->mem, 0, VK_WHOLE_SIZE, 0, (void **)&b->map));
	printf("GVX-VK buffer_bytes=%llu memory_type=%u\n", (unsigned long long)req.size, type);
}

// sync_fd_check exports the fence of one submission as a sync file and waits
// for it with poll. On venus without DRM syncobj this uses
// VIRTGPU_EXECBUF_FENCE_FD_OUT and the sync_file of the device.
static const char *sync_fd_check(VkPhysicalDevice pd, VkDevice dev, VkQueue q, VkCommandBuffer cb) {
	if (!has_extension(pd, VK_KHR_EXTERNAL_FENCE_FD_EXTENSION_NAME)) {
		return "unsupported";
	}
	VkPhysicalDeviceExternalFenceInfo efi = {
		.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_FENCE_INFO,
		.handleType = VK_EXTERNAL_FENCE_HANDLE_TYPE_SYNC_FD_BIT,
	};
	VkExternalFenceProperties efp = {.sType = VK_STRUCTURE_TYPE_EXTERNAL_FENCE_PROPERTIES};
	vkGetPhysicalDeviceExternalFenceProperties(pd, &efi, &efp);
	if (!(efp.externalFenceFeatures & VK_EXTERNAL_FENCE_FEATURE_EXPORTABLE_BIT)) {
		return "unsupported";
	}
	PFN_vkGetFenceFdKHR get_fd = (PFN_vkGetFenceFdKHR)vkGetDeviceProcAddr(dev, "vkGetFenceFdKHR");
	if (get_fd == NULL) {
		return "unsupported";
	}
	VkExportFenceCreateInfo export = {
		.sType = VK_STRUCTURE_TYPE_EXPORT_FENCE_CREATE_INFO,
		.handleTypes = VK_EXTERNAL_FENCE_HANDLE_TYPE_SYNC_FD_BIT,
	};
	VkFenceCreateInfo fci = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO, .pNext = &export};
	VkFence fence;
	CHECK(vkCreateFence(dev, &fci, NULL, &fence));
	VkSubmitInfo si = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &cb};
	CHECK(vkQueueSubmit(q, 1, &si, fence));
	VkFenceGetFdInfoKHR gfi = {
		.sType = VK_STRUCTURE_TYPE_FENCE_GET_FD_INFO_KHR,
		.fence = fence,
		.handleType = VK_EXTERNAL_FENCE_HANDLE_TYPE_SYNC_FD_BIT,
	};
	int fd = -1;
	VkResult r = get_fd(dev, &gfi, &fd);
	const char *result = "FAIL";
	if (r != VK_SUCCESS) {
		printf("GVX-VK syncfd_error=vkGetFenceFdKHR returned %d\n", (int)r);
	} else if (fd == -1) {
		// A signaled fence may export as -1, which Vulkan allows.
		result = "PASS";
	} else {
		struct pollfd p = {.fd = fd, .events = POLLIN};
		int n = poll(&p, 1, 10000);
		if (n == 1 && (p.revents & POLLIN)) {
			result = "PASS";
		} else {
			printf("GVX-VK syncfd_error=poll returned %d revents %#x\n", n, p.revents);
		}
		close(fd);
	}
	vkQueueWaitIdle(q);
	vkDestroyFence(dev, fence, NULL);
	return result;
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc != 2) {
		fprintf(stderr, "usage: vkcompute <shader.spv>\n");
		return 2;
	}
	const char *want = getenv("GVX_VK_DEVICE");
	uint32_t words = env_u32("GVX_VK_WORDS", 1u << 20);
	uint32_t rounds = env_u32("GVX_VK_ROUNDS", 50);
	if (words == 0 || words % LOCAL_SIZE != 0) {
		printf("GVX-VK error=GVX_VK_WORDS must be a positive multiple of %u\nGVX-VK result=FAIL\nGVX-VK done\n", LOCAL_SIZE);
		return 1;
	}

	VkApplicationInfo app = {
		.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
		.pApplicationName = "gvx-vkcompute",
		.apiVersion = VK_API_VERSION_1_2,
	};
	VkInstanceCreateInfo ici = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app};
	VkInstance inst;
	CHECK(vkCreateInstance(&ici, NULL, &inst));

	uint32_t npd = 0;
	CHECK(vkEnumeratePhysicalDevices(inst, &npd, NULL));
	printf("GVX-VK devices=%u\n", npd);
	if (npd == 0) {
		printf("GVX-VK result=FAIL\nGVX-VK done\n");
		return 1;
	}
	VkPhysicalDevice *pds = calloc(npd, sizeof(*pds));
	CHECK(vkEnumeratePhysicalDevices(inst, &npd, pds));
	VkPhysicalDevice pd = VK_NULL_HANDLE;
	for (uint32_t i = 0; i < npd; i++) {
		VkPhysicalDeviceDriverProperties drv = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES};
		VkPhysicalDeviceProperties2 p2 = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, .pNext = &drv};
		vkGetPhysicalDeviceProperties2(pds[i], &p2);
		printf("GVX-VK device%u=%s\n", i, p2.properties.deviceName);
		if (pd == VK_NULL_HANDLE && (want == NULL || strstr(p2.properties.deviceName, want) != NULL)) {
			pd = pds[i];
			printf("GVX-VK device_name=%s\n", p2.properties.deviceName);
			printf("GVX-VK device_type=%d\n", (int)p2.properties.deviceType);
			printf("GVX-VK api_version=%u.%u.%u\n", VK_API_VERSION_MAJOR(p2.properties.apiVersion),
			       VK_API_VERSION_MINOR(p2.properties.apiVersion), VK_API_VERSION_PATCH(p2.properties.apiVersion));
			printf("GVX-VK driver_name=%s\n", drv.driverName);
			printf("GVX-VK driver_info=%s\n", drv.driverInfo);
		}
	}
	if (pd == VK_NULL_HANDLE) {
		printf("GVX-VK error=no device name contains \"%s\"\nGVX-VK result=FAIL\nGVX-VK done\n", want);
		return 1;
	}

	uint32_t nqf = 0;
	vkGetPhysicalDeviceQueueFamilyProperties(pd, &nqf, NULL);
	VkQueueFamilyProperties *qf = calloc(nqf, sizeof(*qf));
	vkGetPhysicalDeviceQueueFamilyProperties(pd, &nqf, qf);
	uint32_t family = UINT32_MAX;
	for (uint32_t i = 0; i < nqf; i++) {
		if (qf[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
			family = i;
			break;
		}
	}
	if (family == UINT32_MAX) {
		printf("GVX-VK error=no compute queue\nGVX-VK result=FAIL\nGVX-VK done\n");
		return 1;
	}

	const char *dev_ext[1];
	uint32_t ndev_ext = 0;
	if (has_extension(pd, VK_KHR_EXTERNAL_FENCE_FD_EXTENSION_NAME)) {
		dev_ext[ndev_ext++] = VK_KHR_EXTERNAL_FENCE_FD_EXTENSION_NAME;
	}
	float prio = 1.0f;
	VkDeviceQueueCreateInfo qci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
		.queueFamilyIndex = family,
		.queueCount = 1,
		.pQueuePriorities = &prio,
	};
	VkDeviceCreateInfo dci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
		.queueCreateInfoCount = 1,
		.pQueueCreateInfos = &qci,
		.enabledExtensionCount = ndev_ext,
		.ppEnabledExtensionNames = dev_ext,
	};
	VkDevice dev;
	CHECK(vkCreateDevice(pd, &dci, NULL, &dev));
	VkQueue q;
	vkGetDeviceQueue(dev, family, 0, &q);

	VkDeviceSize bytes = (VkDeviceSize)words * sizeof(uint32_t);
	struct buffer src, dst;
	create_buffer(pd, dev, bytes, &src);
	create_buffer(pd, dev, bytes, &dst);
	for (uint32_t i = 0; i < words; i++) {
		src.map[i] = source_word(i);
		dst.map[i] = 0xDEADBEEFu;
	}

	size_t spv_size = 0;
	uint32_t *spv = read_file(argv[1], &spv_size);
	if (spv == NULL) {
		printf("GVX-VK result=FAIL\nGVX-VK done\n");
		return 1;
	}
	VkShaderModuleCreateInfo smci = {
		.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
		.codeSize = spv_size,
		.pCode = spv,
	};
	VkShaderModule sm;
	CHECK(vkCreateShaderModule(dev, &smci, NULL, &sm));

	VkDescriptorSetLayoutBinding binds[2] = {
		{.binding = 0, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .descriptorCount = 1,
		 .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT},
		{.binding = 1, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .descriptorCount = 1,
		 .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT},
	};
	VkDescriptorSetLayoutCreateInfo dslci = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
		.bindingCount = 2,
		.pBindings = binds,
	};
	VkDescriptorSetLayout dsl;
	CHECK(vkCreateDescriptorSetLayout(dev, &dslci, NULL, &dsl));
	VkPipelineLayoutCreateInfo plci = {
		.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
		.setLayoutCount = 1,
		.pSetLayouts = &dsl,
	};
	VkPipelineLayout pl;
	CHECK(vkCreatePipelineLayout(dev, &plci, NULL, &pl));
	VkComputePipelineCreateInfo cpci = {
		.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
		.stage = {.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
		          .stage = VK_SHADER_STAGE_COMPUTE_BIT,
		          .module = sm,
		          .pName = "main"},
		.layout = pl,
	};
	VkPipeline pipe;
	CHECK(vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &cpci, NULL, &pipe));

	VkDescriptorPoolSize ps = {.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .descriptorCount = 2};
	VkDescriptorPoolCreateInfo dpci = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
		.maxSets = 1,
		.poolSizeCount = 1,
		.pPoolSizes = &ps,
	};
	VkDescriptorPool dp;
	CHECK(vkCreateDescriptorPool(dev, &dpci, NULL, &dp));
	VkDescriptorSetAllocateInfo dsai = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
		.descriptorPool = dp,
		.descriptorSetCount = 1,
		.pSetLayouts = &dsl,
	};
	VkDescriptorSet ds;
	CHECK(vkAllocateDescriptorSets(dev, &dsai, &ds));
	VkDescriptorBufferInfo dbi[2] = {
		{.buffer = src.buf, .offset = 0, .range = VK_WHOLE_SIZE},
		{.buffer = dst.buf, .offset = 0, .range = VK_WHOLE_SIZE},
	};
	VkWriteDescriptorSet wds[2] = {
		{.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = ds, .dstBinding = 0, .descriptorCount = 1,
		 .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .pBufferInfo = &dbi[0]},
		{.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = ds, .dstBinding = 1, .descriptorCount = 1,
		 .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .pBufferInfo = &dbi[1]},
	};
	vkUpdateDescriptorSets(dev, 2, wds, 0, NULL);

	VkCommandPoolCreateInfo cpi = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = family};
	VkCommandPool cp;
	CHECK(vkCreateCommandPool(dev, &cpi, NULL, &cp));
	VkCommandBufferAllocateInfo cbai = {
		.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
		.commandPool = cp,
		.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
		.commandBufferCount = 1,
	};
	VkCommandBuffer cb;
	CHECK(vkAllocateCommandBuffers(dev, &cbai, &cb));
	VkCommandBufferBeginInfo cbbi = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
	CHECK(vkBeginCommandBuffer(cb, &cbbi));
	vkCmdBindPipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
	vkCmdBindDescriptorSets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, NULL);
	vkCmdDispatch(cb, words / LOCAL_SIZE, 1, 1);
	VkMemoryBarrier mb = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
		.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
		.dstAccessMask = VK_ACCESS_HOST_READ_BIT,
	};
	vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &mb, 0, NULL, 0,
	                     NULL);
	CHECK(vkEndCommandBuffer(cb));

	VkFenceCreateInfo fci = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
	VkFence fence;
	CHECK(vkCreateFence(dev, &fci, NULL, &fence));
	VkSubmitInfo si = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &cb};
	double t0 = now_ms();
	CHECK(vkQueueSubmit(q, 1, &si, fence));
	CHECK(vkWaitForFences(dev, 1, &fence, VK_TRUE, FENCE_TIMEOUT_NS));
	printf("GVX-VK first_dispatch_ms=%.3f\n", now_ms() - t0);

	uint32_t mismatches = 0;
	int64_t first_bad = -1;
	for (uint32_t i = 0; i < words; i++) {
		if (dst.map[i] != expected_word(i, source_word(i))) {
			if (first_bad < 0) {
				first_bad = i;
				printf("GVX-VK first_bad_value=%#x want %#x\n", dst.map[i], expected_word(i, source_word(i)));
			}
			mismatches++;
		}
	}
	printf("GVX-VK checked=%u mismatches=%u first_bad=%lld\n", words, mismatches, (long long)first_bad);
	if (mismatches != 0) {
		failures++;
	}

	// TestE2EGPURendererKill waits for this line, then kills the renderer
	// while the loop runs.
	printf("GVX-VK rounds_begin=%u\n", rounds);
	double total = 0;
	for (uint32_t r = 0; r < rounds; r++) {
		CHECK(vkResetFences(dev, 1, &fence));
		t0 = now_ms();
		CHECK(vkQueueSubmit(q, 1, &si, fence));
		CHECK(vkWaitForFences(dev, 1, &fence, VK_TRUE, FENCE_TIMEOUT_NS));
		total += now_ms() - t0;
	}
	if (rounds > 0) {
		printf("GVX-VK rounds=%u avg_submit_wait_ms=%.3f\n", rounds, total / rounds);
	}

	const char *sync = sync_fd_check(pd, dev, q, cb);
	printf("GVX-VK syncfd=%s\n", sync);
	if (strcmp(sync, "FAIL") == 0) {
		failures++;
	}

	vkDestroyFence(dev, fence, NULL);
	vkDestroyCommandPool(dev, cp, NULL);
	vkDestroyDescriptorPool(dev, dp, NULL);
	vkDestroyPipeline(dev, pipe, NULL);
	vkDestroyPipelineLayout(dev, pl, NULL);
	vkDestroyDescriptorSetLayout(dev, dsl, NULL);
	vkDestroyShaderModule(dev, sm, NULL);
	vkUnmapMemory(dev, src.mem);
	vkUnmapMemory(dev, dst.mem);
	vkDestroyBuffer(dev, src.buf, NULL);
	vkDestroyBuffer(dev, dst.buf, NULL);
	vkFreeMemory(dev, src.mem, NULL);
	vkFreeMemory(dev, dst.mem, NULL);
	vkDestroyDevice(dev, NULL);
	vkDestroyInstance(inst, NULL);
	free(spv);
	free(qf);
	free(pds);

	printf("GVX-VK result=%s\nGVX-VK done\n", failures == 0 ? "PASS" : "FAIL");
	return failures == 0 ? 0 : 1;
}
