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

/*
 * libvulkan.dylib of the renderer bundle. virglrenderer opens
 * "libvulkan.dylib" and looks up vkGetInstanceProcAddr, while the KosmicKrisp
 * ICD exports only the loader interface (vk_icdGetInstanceProcAddr and
 * vk_icdNegotiateLoaderICDInterfaceVersion). This file forwards the one entry
 * point; the bundle uses no Vulkan loader, no ICD manifest, and no layer.
 */

#include <pthread.h>
#include <stdint.h>
#include <vulkan/vulkan.h>

extern PFN_vkVoidFunction vk_icdGetInstanceProcAddr(VkInstance instance, const char *name);
extern VkResult vk_icdNegotiateLoaderICDInterfaceVersion(uint32_t *version);

static pthread_once_t negotiate_once = PTHREAD_ONCE_INIT;
static VkResult negotiate_result = VK_ERROR_INCOMPATIBLE_DRIVER;

static void negotiate(void)
{
	/* Interface version 5 matches KosmicKrisp 26.3.0. */
	uint32_t version = 5;
	negotiate_result = vk_icdNegotiateLoaderICDInterfaceVersion(&version);
}

__attribute__((visibility("default")))
PFN_vkVoidFunction vkGetInstanceProcAddr(VkInstance instance, const char *name)
{
	pthread_once(&negotiate_once, negotiate);
	if (negotiate_result != VK_SUCCESS) {
		return NULL;
	}
	return vk_icdGetInstanceProcAddr(instance, name);
}
