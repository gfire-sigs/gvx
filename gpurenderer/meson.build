project('gvx-gpu-renderer', 'c', 'objc',
  version: '0.1.0',
  meson_version: '>= 1.3.0',
  default_options: [
    'c_std=c11',
    'warning_level=2',
    'werror=true',
    'buildtype=release',
    'default_library=static',
    'b_ndebug=if-release',
  ])

if host_machine.system() != 'darwin' or host_machine.cpu_family() != 'aarch64'
  error('gvx-gpu-renderer builds only for darwin/arm64')
endif

# Build the renderer binary and its static virglrenderer objects for macOS 26.0
# so main() always launches and runs check_macos_version() before dlopen.
add_global_arguments('-mmacosx-version-min=26.0', language: ['c', 'objc'])

vk_inc = get_option('vulkan_include_dir')
if vk_inc == ''
  error('set -Dvulkan_include_dir (scripts/gpu/build-renderer.sh does this)')
endif
build_info = get_option('build_info')
if build_info.substring(55) != ''
  error('build_info is longer than 55 bytes')
endif
min_macos = get_option('min_macos')
if min_macos == ''
  error('set -Dmin_macos (scripts/gpu/build-renderer.sh does this)')
endif

virgl = subproject('virglrenderer', default_options: [
  'venus=true', 'vrend=false',
  'render-server-mode=thread', 'render-server-worker=thread',
  'tests=false', 'video=false', 'tracing=none',
  'default_library=static', 'werror=false',
])

executable('gvx-gpu-renderer',
  'src/main.c', 'src/bundle_darwin.c', 'src/confine_darwin.c', 'src/confine_checks.c',
  'src/vk_probe.c', 'src/wire.c', 'src/server.c', 'src/selftest.c', 'src/watchdog_darwin.c',
  include_directories: include_directories('.', 'selftest', is_system: false),
  c_args: [
    '-mmacosx-version-min=26.0',
    '-D_DARWIN_C_SOURCE',
    '-DVK_NO_PROTOTYPES',
    '-DGVX_RENDERER_VERSION="' + meson.project_version() + '"',
    '-DGVX_RENDERER_BUILD_INFO="' + build_info + '"',
    '-DGVX_RENDERER_MIN_MACOS="' + min_macos + '"',
    '-I' + vk_inc,
    '-Wshadow', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wvla', '-Wformat=2',
  ],
  link_args: ['-mmacosx-version-min=26.0'],
  dependencies: [virgl.get_variable('libvirglrenderer_dep'), dependency('threads')],
  build_rpath: '@executable_path/../lib',
  install_rpath: '@executable_path/../lib',
  install: false)

driver_lib = get_option('driver_lib')
if driver_lib == ''
  error('set -Ddriver_lib (scripts/gpu/build-renderer.sh does this)')
endif
shared_library('vulkan', 'src/vulkan_shim.c',
  c_args: ['-mmacosx-version-min=' + min_macos, '-DVK_NO_PROTOTYPES', '-fvisibility=hidden', '-I' + vk_inc],
  link_args: ['-mmacosx-version-min=' + min_macos, driver_lib],
  name_suffix: 'dylib',
  install: false)
