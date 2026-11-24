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

#include <OpenGL/OpenGL.h>
#include <OpenGL/gl3.h>
#include <stdio.h>
#include <string.h>

static CGLPixelFormatObj g_pf = NULL;
static CGLContextObj g_root_ctx = NULL;
static uint32_t g_live_contexts = 0;
static bool g_cap_logged = false;
static char g_renderer_name[128] = "";

int gl_cgl_init(char *err, size_t err_len)
{
	CGLPixelFormatAttribute attrs[] = {
		kCGLPFAOpenGLProfile, (CGLPixelFormatAttribute)kCGLOGLPVersion_GL4_Core,
		kCGLPFAAccelerated,
		kCGLPFAAllowOfflineRenderers,
		kCGLPFANoRecovery,
		(CGLPixelFormatAttribute)0,
	};

	GLint npix = 0;
	CGLError cerr = CGLChoosePixelFormat(attrs, &g_pf, &npix);
	if (cerr != kCGLNoError || g_pf == NULL) {
		if (g_pf != NULL) {
			CGLReleasePixelFormat(g_pf);
			g_pf = NULL;
		}
		snprintf(err, err_len, "CGLChoosePixelFormat: %s", CGLErrorString(cerr));
		return -1;
	}

	CGLContextObj probe = NULL;
	cerr = CGLCreateContext(g_pf, NULL, &probe);
	if (cerr != kCGLNoError || probe == NULL) {
		CGLReleasePixelFormat(g_pf);
		g_pf = NULL;
		snprintf(err, err_len, "CGLCreateContext: %s", CGLErrorString(cerr));
		return -1;
	}

	cerr = CGLSetCurrentContext(probe);
	if (cerr != kCGLNoError) {
		(void)CGLDestroyContext(probe);
		CGLReleasePixelFormat(g_pf);
		g_pf = NULL;
		snprintf(err, err_len, "CGLSetCurrentContext: %s", CGLErrorString(cerr));
		return -1;
	}

	const char *raw_renderer = (const char *)glGetString(GL_RENDERER);
	const char *raw_version = (const char *)glGetString(GL_VERSION);

	char renderer_buf[128];
	char version_buf[128];
	renderer_buf[0] = '\0';
	version_buf[0] = '\0';
	if (raw_renderer != NULL) {
		snprintf(renderer_buf, sizeof(renderer_buf), "%s", raw_renderer);
	}
	if (raw_version != NULL) {
		snprintf(version_buf, sizeof(version_buf), "%s", raw_version);
	}

	(void)CGLSetCurrentContext(NULL);
	(void)CGLDestroyContext(probe);

	if (renderer_buf[0] == '\0' || version_buf[0] == '\0') {
		CGLReleasePixelFormat(g_pf);
		g_pf = NULL;
		snprintf(err, err_len, "glGetString returned empty GL_RENDERER or GL_VERSION");
		return -1;
	}
	if (strncmp(version_buf, "4.1", 3) != 0) {
		CGLReleasePixelFormat(g_pf);
		g_pf = NULL;
		snprintf(err, err_len, "OpenGL version %s is not 4.1 core (renderer: %s)",
		         version_buf, renderer_buf);
		return -1;
	}
	if (strstr(renderer_buf, "Software") != NULL ||
	    strstr(renderer_buf, "Generic") != NULL) {
		CGLReleasePixelFormat(g_pf);
		g_pf = NULL;
		snprintf(err, err_len, "software OpenGL renderer rejected: %s (%s)",
		         renderer_buf, version_buf);
		return -1;
	}

	snprintf(g_renderer_name, sizeof(g_renderer_name), "%s", renderer_buf);
	fprintf(stderr, "gvx-gpu-renderer: OpenGL: %s, %s\n", g_renderer_name, version_buf);
	return 0;
}

const char *gl_cgl_renderer(void)
{
	return g_renderer_name;
}

virgl_renderer_gl_context gl_cgl_create_context(void *cookie,
                                                int scanout_idx,
                                                struct virgl_renderer_gl_ctx_param *param)
{
	(void)cookie;
	(void)scanout_idx;

	if (g_pf == NULL || param == NULL) {
		return NULL;
	}
	if (param->compat_ctx ||
	    param->major_ver > 4 ||
	    (param->major_ver == 4 && param->minor_ver > 1)) {
		return NULL;
	}
	if (g_live_contexts >= GL_CGL_MAX_CONTEXTS) {
		if (!g_cap_logged) {
			g_cap_logged = true;
			fprintf(stderr, "gvx-gpu-renderer: CGL context limit reached (%u)\n",
			        GL_CGL_MAX_CONTEXTS);
		}
		return NULL;
	}
	if (param->shared && g_root_ctx == NULL) {
		return NULL;
	}

	CGLContextObj share = param->shared ? g_root_ctx : NULL;
	CGLContextObj ctx = NULL;
	CGLError cerr = CGLCreateContext(g_pf, share, &ctx);
	if (cerr != kCGLNoError || ctx == NULL) {
		fprintf(stderr, "gvx-gpu-renderer: CGLCreateContext: %s\n", CGLErrorString(cerr));
		return NULL;
	}

	if (!param->shared && g_root_ctx == NULL) {
		g_root_ctx = ctx;
	}
	g_live_contexts++;
	return ctx;
}

void gl_cgl_destroy_context(void *cookie, virgl_renderer_gl_context ctx)
{
	(void)cookie;
	if (ctx == NULL) {
		return;
	}
	CGLContextObj cgl = (CGLContextObj)ctx;
	if (CGLGetCurrentContext() == cgl) {
		glFlush();
		(void)CGLSetCurrentContext(NULL);
	}
	if (cgl == g_root_ctx) {
		g_root_ctx = NULL;
	}
	(void)CGLDestroyContext(cgl);
	if (g_live_contexts > 0) {
		g_live_contexts--;
	}
}

int gl_cgl_make_current(void *cookie, int scanout_idx, virgl_renderer_gl_context ctx)
{
	(void)cookie;
	(void)scanout_idx;
	/* CGLSetCurrentContext does not flush the old context. Flush before
	 * switching so shared contexts observe prior commands and fences. */
	CGLContextObj cur = CGLGetCurrentContext();
	if (cur != NULL && cur != (CGLContextObj)ctx) {
		glFlush();
	}
	CGLError cerr = CGLSetCurrentContext((CGLContextObj)ctx);
	return cerr == kCGLNoError ? 0 : -1;
}

uint32_t gl_cgl_live_contexts(void)
{
	return g_live_contexts;
}
