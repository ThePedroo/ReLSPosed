#pragma once

#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t get_pkg_from_classpath_arg(const char* classpath_dir, char* package_name, size_t package_name_buffer_size);

#ifdef __cplusplus
}
#endif