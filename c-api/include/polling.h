/*
 * Copyright (C) 2023 smol-rs project, MIT/Apache2.0 License
 */

#ifndef SMOL_POLLING_H
#define SMOL_POLLING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct polling polling_t;
typedef struct polling_event polling_event_t;
typedef struct polling_events polling_events_t;
typedef struct polling_timeout polling_timeout_t;
typedef enum polling_mode polling_mode_t;
typedef enum polling_status polling_status_t;

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
typedef SOCKET polling_source_t;
#else
typedef int polling_source_t;
#endif

struct polling_event {
    // The unique ID to use.
    uintptr_t key;

    // Whether to poll for read events.
    int readable;

    // Whether to poll for write events.
    int writable;
};

struct polling_timeout {
    // The number of seconds to wait.
    uint64_t seconds;

    // The number of nanoseconds to wait.
    uint32_t nanoseconds;
};

enum polling_mode {
    // Poll for oneshot mode.
    POLLING_MODE_ONESHOT = 0,

    // Poll for level-triggered mode.
    POLLING_MODE_LEVEL,

    // Poll for edge-triggered mode.
    POLLING_MODE_EDGE,

    POLLING_MODE_COUNT
};

enum polling_status {
    // No error.
    POLLING_STATUS_OK = 0,

    // The provided value is invalid.
    POLLING_STATUS_INVALID,

    // The operation is not supported.
    POLLING_STATUS_UNSUPPORTED,

    // Another I/O error occurred.
    POLLING_STATUS_IO,

    // Attempted to access memory out of range.
    POLLING_STATUS_OUT_OF_RANGE,

    POLLING_STATUS_COUNT
};

/* polling_poller_t API */

// Create a new poller.
polling_status_t polling_new(polling_t **poller);

// Destroy a poller.
void polling_free(polling_t *poller);

// Add a new event to the poller.
polling_status_t polling_add(
    const polling_t const *poller,
    polling_source_t source,
    const polling_event_t const *interest,
    polling_mode_t mode
);

// Modify an existing event in the poller.
polling_status_t polling_modify(
    const polling_t const *poller,
    polling_source_t source,
    const polling_event_t const *interest,
    polling_mode_t mode
);

// Remove an existing event from the poller.
polling_status_t polling_delete(const polling_t const *poller, polling_source_t source);

// Wait for incoming events.
polling_status_t polling_wait(
    const polling_t const *poller,
    polling_events_t *events,
    const polling_timeout_t const *timeout,
    size_t *num_events
);

// Notify the poller that an event has occurred.
polling_status_t polling_notify(const polling_t const *poller);

/* polling_events_t API */

// Create a new container for events.
polling_status_t polling_events_new(polling_events_t **events);

// Create a new container for events with a given capacity.
polling_status_t polling_events_with_capacity(size_t capacity, polling_events_t **events);

// Destroy a container for events.
void polling_events_free(polling_events_t *events);

// Get the number of events in the container.
size_t polling_events_len(const polling_events_t const *events);

// Get the event at the given index.
polling_status_t polling_events_get(
    const polling_events_t const *events,
    size_t index,
    polling_event_t *event
);

// Clear all events from the container.
void polling_events_clear(polling_events_t *events);

// Copy the events to a buffer.
size_t polling_events_copy(
    const polling_events_t const *events,
    polling_event_t *buffer,
    size_t buffer_len
);

#ifdef __cplusplus
}
#endif

#endif
