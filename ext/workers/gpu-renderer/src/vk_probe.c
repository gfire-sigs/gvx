/*
 * Copyright 2026 The gVisor Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "renderer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "probe_spv.h"

_Static_assert(sizeof(gvx_selftest_spv) % sizeof(uint32_t) == 0,
               "SPIR-V shader size must be a multiple of 4 bytes");

struct vk_funcs {
	PFN_vkCreateInstance create_instance;
	PFN_vkDestroyInstance destroy_instance;
	PFN_vkEnumeratePhysicalDevices enumerate_physical_devices;
	PFN_vkEnumerateDeviceExtensionProperties enumerate_device_extension_properties;
	PFN_vkCreateDevice create_device;
	PFN_vkGetDeviceProcAddr get_device_proc_addr;

	PFN_vkDestroyDevice destroy_device;
	PFN_vkGetDeviceQueue get_device_queue;
	PFN_vkCreateBuffer create_buffer;
	PFN_vkDestroyBuffer destroy_buffer;
	PFN_vkGetMemoryHostPointerPropertiesEXT get_memory_host_pointer_properties;
	PFN_vkAllocateMemory allocate_memory;
	PFN_vkFreeMemory free_memory;
	PFN_vkBindBufferMemory bind_buffer_memory;
	PFN_vkCreateShaderModule create_shader_module;
	PFN_vkDestroyShaderModule destroy_shader_module;
	PFN_vkCreateDescriptorSetLayout create_descriptor_set_layout;
	PFN_vkDestroyDescriptorSetLayout destroy_descriptor_set_layout;
	PFN_vkCreatePipelineLayout create_pipeline_layout;
	PFN_vkDestroyPipelineLayout destroy_pipeline_layout;
	PFN_vkCreateComputePipelines create_compute_pipelines;
	PFN_vkDestroyPipeline destroy_pipeline;
	PFN_vkCreateDescriptorPool create_descriptor_pool;
	PFN_vkDestroyDescriptorPool destroy_descriptor_pool;
	PFN_vkAllocateDescriptorSets allocate_descriptor_sets;
	PFN_vkUpdateDescriptorSets update_descriptor_sets;
	PFN_vkCreateCommandPool create_command_pool;
	PFN_vkDestroyCommandPool destroy_command_pool;
	PFN_vkAllocateCommandBuffers allocate_command_buffers;
	PFN_vkBeginCommandBuffer begin_command_buffer;
	PFN_vkCmdBindPipeline cmd_bind_pipeline;
	PFN_vkCmdBindDescriptorSets cmd_bind_descriptor_sets;
	PFN_vkCmdDispatch cmd_dispatch;
	PFN_vkEndCommandBuffer end_command_buffer;
	PFN_vkCreateFence create_fence;
	PFN_vkDestroyFence destroy_fence;
	PFN_vkQueueSubmit queue_submit;
	PFN_vkWaitForFences wait_for_fences;
};

#define LOAD_INST_FN(gipa, inst, field, sym, err, err_len)                          \
	do {                                                                        \
		PFN_vkVoidFunction fn_ = (gipa)((inst), (sym));                     \
		if (fn_ == NULL) {                                                  \
			snprintf((err), (err_len), "missing Vulkan symbol %s", sym); \
			return -1;                                                  \
		}                                                                   \
		memcpy(&(field), &fn_, sizeof(field));                              \
	} while (0)

#define LOAD_DEV_FN(gdpa, dev, field, sym, err, err_len)                            \
	do {                                                                        \
		PFN_vkVoidFunction fn_ = (gdpa)((dev), (sym));                      \
		if (fn_ == NULL) {                                                  \
			snprintf((err), (err_len), "missing Vulkan symbol %s", sym); \
			return -1;                                                  \
		}                                                                   \
		memcpy(&(field), &fn_, sizeof(field));                              \
	} while (0)

/*
 * Fills names[] with the device extensions to enable on pd. Always enables
 * VK_EXT_external_memory_host so virglrenderer can import blob memory on macOS.
 * Enables VK_KHR_portability_subset only when the driver lists it. Returns the
 * extension count, or -1 with a message in err when VK_EXT_external_memory_host
 * is absent.
 */
static int choose_device_extensions(const struct vk_funcs *f,
                                    VkPhysicalDevice pd,
                                    const char *names[2],
                                    char *err,
                                    size_t err_len)
{
	uint32_t count = 0;
	VkResult vr = f->enumerate_device_extension_properties(pd, NULL, &count, NULL);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkEnumerateDeviceExtensionProperties(count) failed: %d", (int)vr);
		return -1;
	}

	VkExtensionProperties *props = NULL;
	if (count > 0) {
		props = calloc(count, sizeof(*props));
		if (props == NULL) {
			snprintf(err, err_len, "out of memory listing device extensions");
			return -1;
		}
		vr = f->enumerate_device_extension_properties(pd, NULL, &count, props);
		if (vr != VK_SUCCESS && vr != VK_INCOMPLETE) {
			free(props);
			snprintf(err, err_len, "vkEnumerateDeviceExtensionProperties failed: %d", (int)vr);
			return -1;
		}
	}

	bool has_ext_host = false;
	bool has_portability = false;
	for (uint32_t i = 0; i < count; i++) {
		if (strcmp(props[i].extensionName, "VK_EXT_external_memory_host") == 0) {
			has_ext_host = true;
		} else if (strcmp(props[i].extensionName, "VK_KHR_portability_subset") == 0) {
			has_portability = true;
		}
	}
	free(props);

	if (!has_ext_host) {
		snprintf(err, err_len, "missing required Vulkan extension VK_EXT_external_memory_host");
		return -1;
	}

	int n = 0;
	names[n++] = "VK_EXT_external_memory_host";
	if (has_portability) {
		names[n++] = "VK_KHR_portability_subset";
	}
	return n;
}

static int create_probe_device(const struct bundle *b,
                               struct vk_funcs *f,
                               VkInstance *out_inst,
                               VkDevice *out_dev,
                               char *err,
                               size_t err_len)
{
	*out_inst = VK_NULL_HANDLE;
	*out_dev = VK_NULL_HANDLE;

	LOAD_INST_FN(b->get_instance_proc_addr, VK_NULL_HANDLE, f->create_instance,
	             "vkCreateInstance", err, err_len);

	VkApplicationInfo app = {
		.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
		.apiVersion = VK_API_VERSION_1_1,
	};
	VkInstanceCreateInfo ici = {
		.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
		.pApplicationInfo = &app,
	};

	VkInstance inst = VK_NULL_HANDLE;
	VkResult vr = f->create_instance(&ici, NULL, &inst);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateInstance failed: %d", (int)vr);
		return -1;
	}
	*out_inst = inst;

	LOAD_INST_FN(b->get_instance_proc_addr, inst, f->destroy_instance,
	             "vkDestroyInstance", err, err_len);
	LOAD_INST_FN(b->get_instance_proc_addr, inst, f->enumerate_physical_devices,
	             "vkEnumeratePhysicalDevices", err, err_len);
	LOAD_INST_FN(b->get_instance_proc_addr, inst, f->enumerate_device_extension_properties,
	             "vkEnumerateDeviceExtensionProperties", err, err_len);
	LOAD_INST_FN(b->get_instance_proc_addr, inst, f->create_device,
	             "vkCreateDevice", err, err_len);
	LOAD_INST_FN(b->get_instance_proc_addr, inst, f->get_device_proc_addr,
	             "vkGetDeviceProcAddr", err, err_len);

	uint32_t dev_count = 1;
	VkPhysicalDevice pd = VK_NULL_HANDLE;
	vr = f->enumerate_physical_devices(inst, &dev_count, &pd);
	if ((vr != VK_SUCCESS && vr != VK_INCOMPLETE) || dev_count == 0) {
		snprintf(err, err_len, "no Vulkan physical device");
		return -1;
	}

	const char *dev_exts[2];
	int ext_count = choose_device_extensions(f, pd, dev_exts, err, err_len);
	if (ext_count < 0) {
		return -1;
	}

	const float queue_priority = 1.0f;
	VkDeviceQueueCreateInfo qci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
		.queueFamilyIndex = 0,
		.queueCount = 1,
		.pQueuePriorities = &queue_priority,
	};
	VkDeviceCreateInfo dci = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
		.queueCreateInfoCount = 1,
		.pQueueCreateInfos = &qci,
		.enabledExtensionCount = (uint32_t)ext_count,
		.ppEnabledExtensionNames = dev_exts,
	};

	VkDevice dev = VK_NULL_HANDLE;
	vr = f->create_device(pd, &dci, NULL, &dev);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateDevice failed: %d", (int)vr);
		return -1;
	}
	*out_dev = dev;

	LOAD_DEV_FN(f->get_device_proc_addr, dev, f->destroy_device,
	            "vkDestroyDevice", err, err_len);
	return 0;
}

static int load_selftest_device_funcs(struct vk_funcs *f,
                                      VkDevice dev,
                                      char *err,
                                      size_t err_len)
{
	PFN_vkGetDeviceProcAddr gdpa = f->get_device_proc_addr;

	LOAD_DEV_FN(gdpa, dev, f->get_device_queue, "vkGetDeviceQueue", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_buffer, "vkCreateBuffer", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_buffer, "vkDestroyBuffer", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->get_memory_host_pointer_properties,
	            "vkGetMemoryHostPointerPropertiesEXT", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->allocate_memory, "vkAllocateMemory", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->free_memory, "vkFreeMemory", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->bind_buffer_memory, "vkBindBufferMemory", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_shader_module, "vkCreateShaderModule", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_shader_module, "vkDestroyShaderModule", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_descriptor_set_layout,
	            "vkCreateDescriptorSetLayout", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_descriptor_set_layout,
	            "vkDestroyDescriptorSetLayout", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_pipeline_layout, "vkCreatePipelineLayout", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_pipeline_layout, "vkDestroyPipelineLayout", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_compute_pipelines,
	            "vkCreateComputePipelines", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_pipeline, "vkDestroyPipeline", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_descriptor_pool, "vkCreateDescriptorPool", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_descriptor_pool, "vkDestroyDescriptorPool", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->allocate_descriptor_sets,
	            "vkAllocateDescriptorSets", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->update_descriptor_sets, "vkUpdateDescriptorSets", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_command_pool, "vkCreateCommandPool", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_command_pool, "vkDestroyCommandPool", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->allocate_command_buffers,
	            "vkAllocateCommandBuffers", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->begin_command_buffer, "vkBeginCommandBuffer", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->cmd_bind_pipeline, "vkCmdBindPipeline", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->cmd_bind_descriptor_sets,
	            "vkCmdBindDescriptorSets", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->cmd_dispatch, "vkCmdDispatch", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->end_command_buffer, "vkEndCommandBuffer", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->create_fence, "vkCreateFence", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->destroy_fence, "vkDestroyFence", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->queue_submit, "vkQueueSubmit", err, err_len);
	LOAD_DEV_FN(gdpa, dev, f->wait_for_fences, "vkWaitForFences", err, err_len);
	return 0;
}

int vk_probe_device(const struct bundle *b, char *err, size_t err_len)
{
	struct vk_funcs f;
	memset(&f, 0, sizeof(f));
	if (err_len > 0) {
		err[0] = '\0';
	}

	VkInstance inst = VK_NULL_HANDLE;
	VkDevice dev = VK_NULL_HANDLE;
	int rc = create_probe_device(b, &f, &inst, &dev, err, err_len);

	if (dev != VK_NULL_HANDLE && f.destroy_device != NULL) {
		f.destroy_device(dev, NULL);
	}
	if (inst != VK_NULL_HANDLE && f.destroy_instance != NULL) {
		f.destroy_instance(inst, NULL);
	}
	return rc;
}

void vk_selftest(const struct bundle *b,
                 int result[VK_STAGE_COUNT],
                 uint64_t *compile_ms,
                 char *err,
                 size_t err_len)
{
	for (int i = 0; i < VK_STAGE_COUNT; i++) {
		result[i] = -1;
	}
	if (compile_ms != NULL) {
		*compile_ms = 0;
	}
	if (err_len > 0) {
		err[0] = '\0';
	}

	struct vk_funcs f;
	memset(&f, 0, sizeof(f));

	VkInstance inst = VK_NULL_HANDLE;
	VkDevice dev = VK_NULL_HANDLE;
	VkQueue queue = VK_NULL_HANDLE;
	VkShaderModule shader = VK_NULL_HANDLE;
	VkDescriptorSetLayout dsl = VK_NULL_HANDLE;
	VkPipelineLayout pl = VK_NULL_HANDLE;
	VkPipeline pipeline = VK_NULL_HANDLE;
	int shm_fd = -1;
	uint32_t *shm_ptr = MAP_FAILED;
	const size_t shm_size = GVX_GPU_HOST_BLOB_ALIGN;
	VkBuffer buf = VK_NULL_HANDLE;
	VkDeviceMemory mem = VK_NULL_HANDLE;
	VkDescriptorPool dp = VK_NULL_HANDLE;
	VkCommandPool cp = VK_NULL_HANDLE;
	VkFence fence = VK_NULL_HANDLE;
	VkResult vr = VK_SUCCESS;

	struct timespec compile_t0;
	struct timespec compile_t1;
	(void)clock_gettime(CLOCK_MONOTONIC, &compile_t0);

	/* Stage 1: Vulkan instance and device creation. */
	if (create_probe_device(b, &f, &inst, &dev, err, err_len) != 0) {
		goto cleanup;
	}
	if (load_selftest_device_funcs(&f, dev, err, err_len) != 0) {
		goto cleanup;
	}
	f.get_device_queue(dev, 0, 0, &queue);
	result[VK_STAGE_DEVICE] = 0;

	/* Stage 2: compute shader compilation through MTLCompilerService. */
	uint32_t spv_words[sizeof(gvx_selftest_spv) / sizeof(uint32_t)];
	memcpy(spv_words, gvx_selftest_spv, sizeof(gvx_selftest_spv));
	VkShaderModuleCreateInfo smci = {
		.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
		.codeSize = gvx_selftest_spv_len,
		.pCode = spv_words,
	};
	vr = f.create_shader_module(dev, &smci, NULL, &shader);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateShaderModule failed: %d", (int)vr);
		goto cleanup;
	}

	VkDescriptorSetLayoutBinding lb = {
		.binding = 0,
		.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
		.descriptorCount = 1,
		.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT,
	};
	VkDescriptorSetLayoutCreateInfo lci = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
		.bindingCount = 1,
		.pBindings = &lb,
	};
	vr = f.create_descriptor_set_layout(dev, &lci, NULL, &dsl);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateDescriptorSetLayout failed: %d", (int)vr);
		goto cleanup;
	}

	VkPipelineLayoutCreateInfo plci = {
		.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
		.setLayoutCount = 1,
		.pSetLayouts = &dsl,
	};
	vr = f.create_pipeline_layout(dev, &plci, NULL, &pl);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreatePipelineLayout failed: %d", (int)vr);
		goto cleanup;
	}

	VkComputePipelineCreateInfo cpci = {
		.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
		.stage = {
			.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
			.stage = VK_SHADER_STAGE_COMPUTE_BIT,
			.module = shader,
			.pName = "main",
		},
		.layout = pl,
	};
	vr = f.create_compute_pipelines(dev, VK_NULL_HANDLE, 1, &cpci, NULL, &pipeline);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateComputePipelines failed: %d", (int)vr);
		goto cleanup;
	}
	(void)clock_gettime(CLOCK_MONOTONIC, &compile_t1);
	if (compile_ms != NULL) {
		int64_t elapsed_ms =
		    (int64_t)(compile_t1.tv_sec - compile_t0.tv_sec) * 1000 +
		    (int64_t)(compile_t1.tv_nsec - compile_t0.tv_nsec) / 1000000;
		*compile_ms = elapsed_ms > 0 ? (uint64_t)elapsed_ms : 0;
	}
	result[VK_STAGE_SHADER] = 0;

	/* Stage 3: POSIX shm creation and host-pointer import. */
	char shm_name[64];
	snprintf(shm_name, sizeof(shm_name), "/vkr-selftest-%d-%x", (int)getpid(), arc4random());
	shm_fd = shm_open(shm_name, O_CREAT | O_EXCL | O_RDWR, 0600);
	if (shm_fd < 0) {
		snprintf(err, err_len, "shm_open: %s", strerror(errno));
		goto cleanup;
	}
	if (shm_unlink(shm_name) != 0) {
		snprintf(err, err_len, "shm_unlink: %s", strerror(errno));
		goto cleanup;
	}
	if (ftruncate(shm_fd, (off_t)shm_size) != 0) {
		snprintf(err, err_len, "ftruncate: %s", strerror(errno));
		goto cleanup;
	}
	void *mapped = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	if (mapped == MAP_FAILED) {
		snprintf(err, err_len, "mmap: %s", strerror(errno));
		goto cleanup;
	}
	shm_ptr = (uint32_t *)mapped;

	VkExternalMemoryBufferCreateInfo ebi = {
		.sType = VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO,
		.handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT,
	};
	VkBufferCreateInfo bci = {
		.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
		.pNext = &ebi,
		.size = shm_size,
		.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
	};
	vr = f.create_buffer(dev, &bci, NULL, &buf);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateBuffer failed: %d", (int)vr);
		goto cleanup;
	}

	VkMemoryHostPointerPropertiesEXT hp = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_HOST_POINTER_PROPERTIES_EXT,
	};
	vr = f.get_memory_host_pointer_properties(
	    dev, VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT, shm_ptr, &hp);
	if (vr != VK_SUCCESS || hp.memoryTypeBits == 0) {
		snprintf(err, err_len, "vkGetMemoryHostPointerPropertiesEXT failed: %d", (int)vr);
		goto cleanup;
	}

	VkImportMemoryHostPointerInfoEXT imp = {
		.sType = VK_STRUCTURE_TYPE_IMPORT_MEMORY_HOST_POINTER_INFO_EXT,
		.handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT,
		.pHostPointer = shm_ptr,
	};
	VkMemoryAllocateInfo mai = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
		.pNext = &imp,
		.allocationSize = shm_size,
		.memoryTypeIndex = (uint32_t)__builtin_ctz(hp.memoryTypeBits),
	};
	vr = f.allocate_memory(dev, &mai, NULL, &mem);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkAllocateMemory failed: %d", (int)vr);
		goto cleanup;
	}

	vr = f.bind_buffer_memory(dev, buf, mem, 0);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkBindBufferMemory failed: %d", (int)vr);
		goto cleanup;
	}
	result[VK_STAGE_SHM_IMPORT] = 0;

	/* Stage 4: compute dispatch and readback through the shm view. */
	VkDescriptorPoolSize ps = {
		.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
		.descriptorCount = 1,
	};
	VkDescriptorPoolCreateInfo dpci = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
		.maxSets = 1,
		.poolSizeCount = 1,
		.pPoolSizes = &ps,
	};
	vr = f.create_descriptor_pool(dev, &dpci, NULL, &dp);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateDescriptorPool failed: %d", (int)vr);
		goto cleanup;
	}

	VkDescriptorSetAllocateInfo dsai = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
		.descriptorPool = dp,
		.descriptorSetCount = 1,
		.pSetLayouts = &dsl,
	};
	VkDescriptorSet ds = VK_NULL_HANDLE;
	vr = f.allocate_descriptor_sets(dev, &dsai, &ds);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkAllocateDescriptorSets failed: %d", (int)vr);
		goto cleanup;
	}

	VkDescriptorBufferInfo dbi = {
		.buffer = buf,
		.offset = 0,
		.range = VK_WHOLE_SIZE,
	};
	VkWriteDescriptorSet wds = {
		.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
		.dstSet = ds,
		.dstBinding = 0,
		.descriptorCount = 1,
		.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
		.pBufferInfo = &dbi,
	};
	f.update_descriptor_sets(dev, 1, &wds, 0, NULL);

	VkCommandPoolCreateInfo cpi = {
		.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
		.queueFamilyIndex = 0,
	};
	vr = f.create_command_pool(dev, &cpi, NULL, &cp);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateCommandPool failed: %d", (int)vr);
		goto cleanup;
	}

	VkCommandBufferAllocateInfo cbai = {
		.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
		.commandPool = cp,
		.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
		.commandBufferCount = 1,
	};
	VkCommandBuffer cb = VK_NULL_HANDLE;
	vr = f.allocate_command_buffers(dev, &cbai, &cb);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkAllocateCommandBuffers failed: %d", (int)vr);
		goto cleanup;
	}

	VkCommandBufferBeginInfo cbbi = {
		.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
	};
	vr = f.begin_command_buffer(cb, &cbbi);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkBeginCommandBuffer failed: %d", (int)vr);
		goto cleanup;
	}
	f.cmd_bind_pipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
	f.cmd_bind_descriptor_sets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, NULL);
	f.cmd_dispatch(cb, 4, 1, 1);
	vr = f.end_command_buffer(cb);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkEndCommandBuffer failed: %d", (int)vr);
		goto cleanup;
	}

	VkFenceCreateInfo fci = {
		.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
	};
	vr = f.create_fence(dev, &fci, NULL, &fence);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkCreateFence failed: %d", (int)vr);
		goto cleanup;
	}

	VkSubmitInfo si = {
		.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
		.commandBufferCount = 1,
		.pCommandBuffers = &cb,
	};
	vr = f.queue_submit(queue, 1, &si, fence);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkQueueSubmit failed: %d", (int)vr);
		goto cleanup;
	}

	const uint64_t wait_timeout_ns = 5000000000ULL;
	vr = f.wait_for_fences(dev, 1, &fence, VK_TRUE, wait_timeout_ns);
	if (vr != VK_SUCCESS) {
		snprintf(err, err_len, "vkWaitForFences failed: %d", (int)vr);
		goto cleanup;
	}

	for (uint32_t i = 0; i < 4; i++) {
		uint32_t expected = GVX_SELFTEST_BASE_VALUE + i;
		if (shm_ptr[i] != expected) {
			snprintf(err, err_len, "shm_ptr[%u] = %u, want %u", i, shm_ptr[i], expected);
			goto cleanup;
		}
	}
	result[VK_STAGE_GPU_WRITE] = 0;

cleanup:
	if (fence != VK_NULL_HANDLE) {
		f.destroy_fence(dev, fence, NULL);
	}
	if (cp != VK_NULL_HANDLE) {
		f.destroy_command_pool(dev, cp, NULL);
	}
	if (dp != VK_NULL_HANDLE) {
		f.destroy_descriptor_pool(dev, dp, NULL);
	}
	if (buf != VK_NULL_HANDLE) {
		f.destroy_buffer(dev, buf, NULL);
	}
	if (mem != VK_NULL_HANDLE) {
		f.free_memory(dev, mem, NULL);
	}
	if (shm_ptr != MAP_FAILED) {
		(void)munmap(shm_ptr, shm_size);
	}
	if (shm_fd >= 0) {
		(void)close(shm_fd);
	}
	if (pipeline != VK_NULL_HANDLE) {
		f.destroy_pipeline(dev, pipeline, NULL);
	}
	if (pl != VK_NULL_HANDLE) {
		f.destroy_pipeline_layout(dev, pl, NULL);
	}
	if (dsl != VK_NULL_HANDLE) {
		f.destroy_descriptor_set_layout(dev, dsl, NULL);
	}
	if (shader != VK_NULL_HANDLE) {
		f.destroy_shader_module(dev, shader, NULL);
	}
	if (dev != VK_NULL_HANDLE && f.destroy_device != NULL) {
		f.destroy_device(dev, NULL);
	}
	if (inst != VK_NULL_HANDLE && f.destroy_instance != NULL) {
		f.destroy_instance(inst, NULL);
	}
}
