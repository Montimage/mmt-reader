/**
 * version.h — Version string handling and --version output
 *
 * Provides a clean interface for displaying version information:
 *   - version_banner(): prints the full MMT-READER banner
 *   - version_banner_fd(): prints banner to a specific file descriptor
 *   - version_print(): prints a concise --version output
 *   - version(): returns the MMT-SDK version string
 */
#ifndef VERSION_H
#define VERSION_H

#include <stdio.h>

/**
 * Print the full MMT-READER banner (program name, version, build date).
 * @param prog_name Program name (argv[0])
 */
void version_banner(const char *prog_name);

/**
 * Print the full MMT-READER banner to a specific file descriptor.
 * @param prog_name Program name (argv[0])
 * @param fp        File descriptor to write to (e.g. stderr)
 */
void version_banner_fd(const char *prog_name, FILE *fp);

/**
 * Print a concise --version output and exit with code 0.
 */
void version_print(void);

/**
 * Return the MMT-SDK version string.
 * @return Version string (constant, do not free)
 */
const char *version(void);

#endif /* VERSION_H */
