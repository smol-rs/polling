#ifndef SMOL_POLLING_H
#define SMOL_POLLING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
typedef SOCKET raw_source_t;
#else
typedef int raw_source_t;
#endif

#ifndef SMOL_POLLING_PUBLIC
#define SMOL_POLLING_PUBLIC
#endif


typedef enum polling_status_t {
  POLLING_STATUS_OK = 0,
  POLLING_STATUS_INVALID = 1,
  POLLING_STATUS_UNSUPPORTED = 2,
  POLLING_STATUS_IO = 3,
  POLLING_STATUS_OUT_OF_RANGE = 4,
} polling_status_t;

typedef void polling_t;

typedef struct polling_event_t {
  uintptr_t key;
  int readable;
  int writable;
} polling_event_t;

typedef void polling_events_t;

typedef struct polling_timeout_t {
  uint64_t seconds;
  uint32_t nanoseconds;
} polling_timeout_t;

SMOL_POLLING_PUBLIC enum polling_status_t polling_new(polling_t **out);

SMOL_POLLING_PUBLIC void polling_free(polling_t *poller);

SMOL_POLLING_PUBLIC
enum polling_status_t polling_add(const polling_t *poller,
                                  raw_source_t source,
                                  const struct polling_event_t *event,
                                  int mode);

SMOL_POLLING_PUBLIC
enum polling_status_t polling_modify(const polling_t *poller,
                                     raw_source_t source,
                                     const struct polling_event_t *event,
                                     int mode);

SMOL_POLLING_PUBLIC
enum polling_status_t polling_delete(const polling_t *poller,
                                     raw_source_t source);

SMOL_POLLING_PUBLIC
enum polling_status_t polling_wait(const polling_t *poller,
                                   polling_events_t *events,
                                   const struct polling_timeout_t *timeout,
                                   size_t *num_events);

SMOL_POLLING_PUBLIC enum polling_status_t polling_notify(const polling_t *poller);

SMOL_POLLING_PUBLIC enum polling_status_t polling_events_new(polling_events_t **out);

SMOL_POLLING_PUBLIC
enum polling_status_t polling_events_with_capacity(size_t capacity,
                                                   polling_events_t **out);

SMOL_POLLING_PUBLIC void polling_events_free(polling_events_t *events);

SMOL_POLLING_PUBLIC
enum polling_status_t polling_events_len(const polling_events_t *events,
                                         size_t *out);

SMOL_POLLING_PUBLIC
enum polling_status_t polling_events_get(const polling_events_t *events,
                                         size_t index,
                                         struct polling_event_t *out);

SMOL_POLLING_PUBLIC void polling_events_clear(polling_events_t *events);

SMOL_POLLING_PUBLIC
size_t polling_events_copy(const polling_events_t *events,
                           struct polling_event_t *buffer,
                           size_t buffer_len);

#endif /* SMOL_POLLING_H */
