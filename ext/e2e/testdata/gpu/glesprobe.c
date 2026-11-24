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

// glesprobe is the guest OpenGL ES 3.0 probe of gate G3. It creates a
// surfaceless EGL context, draws into a 64x64 RGBA8 framebuffer, verifies
// exact pixel values for fill, scissor, texture upload, and repeated readback,
// and optionally loops alternating clears for the renderer kill test.
//
// Usage: glesprobe
// Environment:
//   GVX_GL_ROUNDS   alternating clear-and-readback rounds after checks (default 0)
//   GVX_GL_EXPECT   informational label printed in output (default: none)
//
// Each result line has the form "GVX-GL key=value". The exit code is 0 only
// when every check passes, 1 on any failure, and 2 on a usage error.

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EGL_PLATFORM_SURFACELESS_MESA
#define EGL_PLATFORM_SURFACELESS_MESA 0x31DD
#endif

#define FB_SIZE 64
#define FB_PIXELS (FB_SIZE * FB_SIZE)
#define FB_BYTES (FB_PIXELS * 4)

static void fail_egl(const char *call) {
	printf("GVX-GL error=%s 0x%x\n", call, (unsigned)eglGetError());
	exit(1);
}

static void fail_gl(const char *call, GLenum err) {
	printf("GVX-GL error=%s 0x%x\n", call, (unsigned)err);
	exit(1);
}

static void check_gl(const char *step) {
	GLenum err = glGetError();
	if (err != GL_NO_ERROR) {
		fail_gl(step, err);
	}
}

static int has_egl_extension(const char *exts, const char *name) {
	if (exts == NULL) {
		return 0;
	}
	size_t nlen = strlen(name);
	const char *p = exts;
	while ((p = strstr(p, name)) != NULL) {
		int start_ok = (p == exts || p[-1] == ' ');
		int end_ok = (p[nlen] == '\0' || p[nlen] == ' ');
		if (start_ok && end_ok) {
			return 1;
		}
		p += nlen;
	}
	return 0;
}

static GLuint compile_shader(GLenum type, const char *src, const char *name) {
	GLuint sh = glCreateShader(type);
	if (sh == 0) {
		fail_gl(name, glGetError());
	}
	glShaderSource(sh, 1, &src, NULL);
	glCompileShader(sh);
	GLint ok = 0;
	glGetShaderiv(sh, GL_COMPILE_STATUS, &ok);
	if (!ok) {
		char log[512];
		GLsizei len = 0;
		glGetShaderInfoLog(sh, (GLsizei)sizeof(log), &len, log);
		for (GLsizei i = 0; i < len; i++) {
			if (log[i] == '\n' || log[i] == '\r') {
				log[i] = ' ';
			}
		}
		printf("GVX-GL error=compile_%s %s\n", name, log);
		exit(1);
	}
	return sh;
}

static GLuint link_program(const char *vs_src, const char *fs_src, const char *name) {
	GLuint vs = compile_shader(GL_VERTEX_SHADER, vs_src, name);
	GLuint fs = compile_shader(GL_FRAGMENT_SHADER, fs_src, name);
	GLuint prog = glCreateProgram();
	if (prog == 0) {
		fail_gl(name, glGetError());
	}
	glAttachShader(prog, vs);
	glAttachShader(prog, fs);
	glLinkProgram(prog);
	glDeleteShader(vs);
	glDeleteShader(fs);
	GLint ok = 0;
	glGetProgramiv(prog, GL_LINK_STATUS, &ok);
	if (!ok) {
		char log[512];
		GLsizei len = 0;
		glGetProgramInfoLog(prog, (GLsizei)sizeof(log), &len, log);
		for (GLsizei i = 0; i < len; i++) {
			if (log[i] == '\n' || log[i] == '\r') {
				log[i] = ' ';
			}
		}
		printf("GVX-GL error=link_%s %s\n", name, log);
		exit(1);
	}
	return prog;
}

static int pixel_eq(const uint8_t *px, uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
	return px[0] == r && px[1] == g && px[2] == b && px[3] == a;
}

static uint32_t env_u32(const char *name, uint32_t def) {
	const char *v = getenv(name);
	if (v == NULL || *v == '\0') {
		return def;
	}
	char *end = NULL;
	unsigned long val = strtoul(v, &end, 0);
	if (end == v || *end != '\0') {
		printf("GVX-GL error=invalid %s=%s\n", name, v);
		exit(2);
	}
	return (uint32_t)val;
}

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (argc != 1) {
		fprintf(stderr, "usage: glesprobe\n");
		return 2;
	}

	const char *expect = getenv("GVX_GL_EXPECT");
	if (expect != NULL && *expect != '\0') {
		printf("GVX-GL expect=%s\n", expect);
	}
	uint32_t rounds = env_u32("GVX_GL_ROUNDS", 0);

	PFNEGLGETPLATFORMDISPLAYEXTPROC get_platform_display =
		(PFNEGLGETPLATFORMDISPLAYEXTPROC)eglGetProcAddress("eglGetPlatformDisplayEXT");
	if (get_platform_display == NULL) {
		fail_egl("eglGetProcAddress");
	}
	EGLDisplay dpy = get_platform_display(EGL_PLATFORM_SURFACELESS_MESA, EGL_DEFAULT_DISPLAY, NULL);
	if (dpy == EGL_NO_DISPLAY) {
		fail_egl("eglGetPlatformDisplayEXT");
	}
	EGLint major = 0, minor = 0;
	if (!eglInitialize(dpy, &major, &minor)) {
		fail_egl("eglInitialize");
	}
	const char *egl_exts = eglQueryString(dpy, EGL_EXTENSIONS);
	if (!has_egl_extension(egl_exts, "EGL_KHR_surfaceless_context")) {
		printf("GVX-GL error=missing EGL_KHR_surfaceless_context\n");
		return 1;
	}
	if (!eglBindAPI(EGL_OPENGL_ES_API)) {
		fail_egl("eglBindAPI");
	}
	const EGLint cfg_attrs[] = {
		EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
		EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
		EGL_RED_SIZE, 8,
		EGL_GREEN_SIZE, 8,
		EGL_BLUE_SIZE, 8,
		EGL_ALPHA_SIZE, 8,
		EGL_NONE,
	};
	EGLConfig cfg = NULL;
	EGLint num_cfg = 0;
	if (!eglChooseConfig(dpy, cfg_attrs, &cfg, 1, &num_cfg) || num_cfg < 1) {
		fail_egl("eglChooseConfig");
	}
	const EGLint ctx_attrs[] = {
		EGL_CONTEXT_MAJOR_VERSION, 3,
		EGL_CONTEXT_MINOR_VERSION, 0,
		EGL_NONE,
	};
	EGLContext ctx = eglCreateContext(dpy, cfg, EGL_NO_CONTEXT, ctx_attrs);
	if (ctx == EGL_NO_CONTEXT) {
		fail_egl("eglCreateContext");
	}
	if (!eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, ctx)) {
		fail_egl("eglMakeCurrent");
	}

	const char *egl_vendor = eglQueryString(dpy, EGL_VENDOR);
	const char *egl_version = eglQueryString(dpy, EGL_VERSION);
	const char *gl_vendor = (const char *)glGetString(GL_VENDOR);
	const char *gl_renderer = (const char *)glGetString(GL_RENDERER);
	const char *gl_version = (const char *)glGetString(GL_VERSION);
	const char *glsl_version = (const char *)glGetString(GL_SHADING_LANGUAGE_VERSION);
	printf("GVX-GL egl_vendor=%s\n", egl_vendor ? egl_vendor : "");
	printf("GVX-GL egl_version=%s\n", egl_version ? egl_version : "");
	printf("GVX-GL gl_vendor=%s\n", gl_vendor ? gl_vendor : "");
	printf("GVX-GL gl_renderer=%s\n", gl_renderer ? gl_renderer : "");
	printf("GVX-GL gl_version=%s\n", gl_version ? gl_version : "");
	printf("GVX-GL glsl_version=%s\n", glsl_version ? glsl_version : "");
	check_gl("egl");

	int failures = 0;

	// Step: fbo
	GLuint fbo_tex = 0, fbo = 0;
	glGenTextures(1, &fbo_tex);
	glBindTexture(GL_TEXTURE_2D, fbo_tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, FB_SIZE, FB_SIZE, 0, GL_RGBA, GL_UNSIGNED_BYTE, NULL);

	glGenFramebuffers(1, &fbo);
	glBindFramebuffer(GL_FRAMEBUFFER, fbo);
	glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, fbo_tex, 0);
	GLenum fbo_status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
	if (fbo_status != GL_FRAMEBUFFER_COMPLETE) {
		fail_gl("glCheckFramebufferStatus", fbo_status);
	}
	glViewport(0, 0, FB_SIZE, FB_SIZE);
	check_gl("fbo");
	printf("GVX-GL check_fbo=PASS\n");

	// Full-screen triangle covering clip space [-1, 1]^2.
	static const float tri_verts[6] = {
		-1.0f, -1.0f,
		 3.0f, -1.0f,
		-1.0f,  3.0f,
	};
	GLuint vao = 0, vbo = 0;
	glGenVertexArrays(1, &vao);
	glBindVertexArray(vao);
	glGenBuffers(1, &vbo);
	glBindBuffer(GL_ARRAY_BUFFER, vbo);
	glBufferData(GL_ARRAY_BUFFER, sizeof(tri_verts), tri_verts, GL_STATIC_DRAW);

	// Step: fill
	static const char *vs_src =
		"#version 300 es\n"
		"in vec2 pos;\n"
		"void main() {\n"
		"  gl_Position = vec4(pos, 0.0, 1.0);\n"
		"}\n";
	static const char *fs_fill_src =
		"#version 300 es\n"
		"precision highp float;\n"
		"uniform vec4 color;\n"
		"out vec4 fragColor;\n"
		"void main() {\n"
		"  fragColor = color;\n"
		"}\n";
	GLuint prog_fill = link_program(vs_src, fs_fill_src, "fill");
	GLint pos_loc = glGetAttribLocation(prog_fill, "pos");
	GLint color_loc = glGetUniformLocation(prog_fill, "color");
	if (pos_loc < 0 || color_loc < 0) {
		printf("GVX-GL error=fill_locations pos=%d color=%d\n", pos_loc, color_loc);
		return 1;
	}
	glEnableVertexAttribArray((GLuint)pos_loc);
	glVertexAttribPointer((GLuint)pos_loc, 2, GL_FLOAT, GL_FALSE, 0, (const void *)0);

	glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT);
	glUseProgram(prog_fill);
	glUniform4f(color_loc, 64.0f / 255.0f, 128.0f / 255.0f, 192.0f / 255.0f, 1.0f);
	glDrawArrays(GL_TRIANGLES, 0, 3);

	uint8_t pixels[FB_BYTES];
	glReadPixels(0, 0, FB_SIZE, FB_SIZE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
	check_gl("fill");
	int fill_bad = 0;
	for (int y = 0; y < FB_SIZE && !fill_bad; y++) {
		for (int x = 0; x < FB_SIZE; x++) {
			const uint8_t *p = &pixels[(y * FB_SIZE + x) * 4];
			if (!pixel_eq(p, 64, 128, 192, 255)) {
				printf("GVX-GL check_fill=FAIL %d,%d got %u,%u,%u,%u\n",
				       x, y, p[0], p[1], p[2], p[3]);
				fill_bad = 1;
				failures++;
				break;
			}
		}
	}
	if (!fill_bad) {
		printf("GVX-GL check_fill=PASS\n");
	}

	// Step: scissor
	glEnable(GL_SCISSOR_TEST);
	glScissor(0, 0, 32, FB_SIZE);
	glClearColor(1.0f, 0.0f, 0.0f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT);
	glDisable(GL_SCISSOR_TEST);
	glReadPixels(0, 0, FB_SIZE, FB_SIZE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
	check_gl("scissor");
	int scissor_bad = 0;
	for (int y = 0; y < FB_SIZE && !scissor_bad; y++) {
		for (int x = 0; x < FB_SIZE; x++) {
			const uint8_t *p = &pixels[(y * FB_SIZE + x) * 4];
			int ok = (x < 32) ? pixel_eq(p, 255, 0, 0, 255) : pixel_eq(p, 64, 128, 192, 255);
			if (!ok) {
				printf("GVX-GL check_scissor=FAIL %d,%d got %u,%u,%u,%u\n",
				       x, y, p[0], p[1], p[2], p[3]);
				scissor_bad = 1;
				failures++;
				break;
			}
		}
	}
	if (!scissor_bad) {
		printf("GVX-GL check_scissor=PASS\n");
	}

	// Step: texture
	static const uint8_t texels[2 * 2 * 4] = {
		255,   0,   0, 255, // (0,0) red
		  0, 255,   0, 255, // (1,0) green
		  0,   0, 255, 255, // (0,1) blue
		255, 255, 255, 255, // (1,1) white
	};
	GLuint src_tex = 0;
	glGenTextures(1, &src_tex);
	glActiveTexture(GL_TEXTURE0);
	glBindTexture(GL_TEXTURE_2D, src_tex);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, 0);
	glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 2, 2, 0, GL_RGBA, GL_UNSIGNED_BYTE, texels);

	static const char *fs_tex_src =
		"#version 300 es\n"
		"precision highp float;\n"
		"uniform sampler2D tex;\n"
		"out vec4 fragColor;\n"
		"void main() {\n"
		"  fragColor = texelFetch(tex, ivec2(gl_FragCoord.xy) / 32, 0);\n"
		"}\n";
	GLuint prog_tex = link_program(vs_src, fs_tex_src, "texture");
	GLint tex_pos_loc = glGetAttribLocation(prog_tex, "pos");
	GLint tex_uni_loc = glGetUniformLocation(prog_tex, "tex");
	if (tex_pos_loc < 0 || tex_uni_loc < 0) {
		printf("GVX-GL error=texture_locations pos=%d tex=%d\n", tex_pos_loc, tex_uni_loc);
		return 1;
	}
	glUseProgram(prog_tex);
	glUniform1i(tex_uni_loc, 0);
	glEnableVertexAttribArray((GLuint)tex_pos_loc);
	glVertexAttribPointer((GLuint)tex_pos_loc, 2, GL_FLOAT, GL_FALSE, 0, (const void *)0);
	glDrawArrays(GL_TRIANGLES, 0, 3);
	glReadPixels(0, 0, FB_SIZE, FB_SIZE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
	check_gl("texture");

	static const struct {
		int x, y;
		uint8_t r, g, b, a;
	} quads[4] = {
		{16, 16, 255,   0,   0, 255},
		{48, 16,   0, 255,   0, 255},
		{16, 48,   0,   0, 255, 255},
		{48, 48, 255, 255, 255, 255},
	};
	int tex_bad = 0;
	for (int i = 0; i < 4; i++) {
		const uint8_t *p = &pixels[(quads[i].y * FB_SIZE + quads[i].x) * 4];
		if (!pixel_eq(p, quads[i].r, quads[i].g, quads[i].b, quads[i].a)) {
			printf("GVX-GL check_texture=FAIL %d,%d got %u,%u,%u,%u\n",
			       quads[i].x, quads[i].y, p[0], p[1], p[2], p[3]);
			tex_bad = 1;
			failures++;
			break;
		}
	}
	if (!tex_bad) {
		printf("GVX-GL check_texture=PASS\n");
	}

	// Step: readback
	glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
	glClear(GL_COLOR_BUFFER_BIT);
	glUseProgram(prog_fill);
	glEnableVertexAttribArray((GLuint)pos_loc);
	glVertexAttribPointer((GLuint)pos_loc, 2, GL_FLOAT, GL_FALSE, 0, (const void *)0);
	glUniform4f(color_loc, 12.0f / 255.0f, 34.0f / 255.0f, 56.0f / 255.0f, 1.0f);
	glDrawArrays(GL_TRIANGLES, 0, 3);

	uint8_t pixels2[FB_BYTES];
	glReadPixels(0, 0, FB_SIZE, FB_SIZE, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
	glReadPixels(0, 0, FB_SIZE, FB_SIZE, GL_RGBA, GL_UNSIGNED_BYTE, pixels2);
	check_gl("readback");
	if (memcmp(pixels, pixels2, FB_BYTES) != 0) {
		printf("GVX-GL check_readback=FAIL buffers differ\n");
		failures++;
	} else if (!pixel_eq(pixels, 12, 34, 56, 255)) {
		printf("GVX-GL check_readback=FAIL 0,0 got %u,%u,%u,%u\n",
		       pixels[0], pixels[1], pixels[2], pixels[3]);
		failures++;
	} else {
		printf("GVX-GL check_readback=PASS\n");
	}

	check_gl("final");
	printf("GVX-GL check_glerror=PASS\n");
	printf("GVX-GL result=%s\n", failures == 0 ? "PASS" : "FAIL");
	if (failures != 0) {
		return 1;
	}

	if (rounds > 0) {
		printf("GVX-GL rounds_begin=%u\n", rounds);
		fflush(stdout);
		for (uint32_t i = 0; i < rounds; i++) {
			uint8_t want_r = (i % 2 == 0) ? 16 : 200;
			uint8_t want_g = (i % 2 == 0) ? 32 : 100;
			uint8_t want_b = (i % 2 == 0) ? 48 : 50;
			glClearColor((float)want_r / 255.0f, (float)want_g / 255.0f, (float)want_b / 255.0f, 1.0f);
			glClear(GL_COLOR_BUFFER_BIT);
			uint8_t px[4] = {0, 0, 0, 0};
			glReadPixels(8, 8, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, px);
			GLenum err = glGetError();
			if (err != GL_NO_ERROR) {
				printf("GVX-GL error=round %u glGetError 0x%x\n", i, (unsigned)err);
				return 1;
			}
			if (!pixel_eq(px, want_r, want_g, want_b, 255)) {
				printf("GVX-GL error=round %u pixel %u,%u,%u,%u want %u,%u,%u,255\n",
				       i, px[0], px[1], px[2], px[3], want_r, want_g, want_b);
				return 1;
			}
		}
		printf("GVX-GL rounds_end=%u\n", rounds);
	}

	glDeleteProgram(prog_tex);
	glDeleteProgram(prog_fill);
	glDeleteTextures(1, &src_tex);
	glDeleteBuffers(1, &vbo);
	glDeleteVertexArrays(1, &vao);
	glDeleteFramebuffers(1, &fbo);
	glDeleteTextures(1, &fbo_tex);
	eglMakeCurrent(dpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
	eglDestroyContext(dpy, ctx);
	eglTerminate(dpy);
	return 0;
}
