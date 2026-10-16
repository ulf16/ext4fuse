/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHARED_OVERLAY_H
#define SHARED_OVERLAY_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
struct overlay;
extern struct overlay *active_overlay;
struct overlay *overlay_open(const char *path, size_t max_pages);
void overlay_close(struct overlay *t);
void overlay_rollback(struct overlay *t);
int overlay_publish(struct overlay *t);
void overlay_suspend(struct overlay *t);
int overlay_read(struct overlay *t, uint64_t off, size_t n, void *buf,
                 int reader);
int overlay_write(struct overlay *t, uint64_t off, size_t n, const void *buf);
/* Serialized published overlay only; emits E4OVL001 protocol to a stream. */
int overlay_stream(struct overlay *t, int fd);
int overlay_export(struct overlay *t, const char *output, long fail_page);
void overlay_fail_writes(struct overlay *t, long after);
size_t overlay_pages(struct overlay *t);
/* Unique view revision; zero disables validation reuse after counter exhaustion. */
uint64_t overlay_epoch(struct overlay *t);
const char *overlay_path(struct overlay *t);
int reader_attach(const char *path);
int reader_refresh(void);
int reader_metadata(const char *path, uint64_t *size, unsigned *mode);
int reader_verify(const char *path, const void *data, size_t n);
int reader_absent(const char *path);
#endif
