include($ENV{PW_ROOT}/pw_build/pigweed.cmake)

add_library(suppress_zephyr_warnings INTERFACE)
target_compile_options(suppress_zephyr_warnings INTERFACE
    -Wno-undef
    -Wno-redundant-decls
)

pw_add_module_library(pw_sys_io.nrfconnect
    SOURCES
      sys_io_nrfconnect.cc
    PRIVATE_DEPS
      zephyr_interface
      pw_sys_io
      suppress_zephyr_warnings
)
