//! Implementation of the C API for the `polling` crate.

#![allow(clippy::missing_safety_doc, non_camel_case_types)]

use libc::{c_int, c_void, size_t};
use polling::{Event, PollMode, Poller};
use std::io;

#[cfg(windows)]
/// cbindgen::ignore
pub type raw_source_t = std::os::windows::io::RawSocket;
#[cfg(unix)]
/// cbindgen::ignore
pub type raw_source_t = std::os::unix::io::RawFd;

type polling_t = c_void;
type polling_events_t = c_void;

#[repr(C)]
pub struct polling_event_t {
    key: usize,
    readable: c_int,
    writable: c_int,
}

#[repr(C)]
pub struct polling_timeout_t {
    seconds: u64,
    nanoseconds: u32,
}

#[repr(C)]
pub enum polling_mode_t {
    POLLING_MODE_ONESHOT = 0,
    POLLING_MODE_LEVEL = 1,
    POLLING_MODE_EDGE = 2,
}

impl polling_mode_t {
    fn from_int(value: c_int) -> Option<Self> {
        match value {
            0 => Some(polling_mode_t::POLLING_MODE_ONESHOT),
            1 => Some(polling_mode_t::POLLING_MODE_LEVEL),
            2 => Some(polling_mode_t::POLLING_MODE_EDGE),
            _ => None,
        }
    }
}

#[repr(C)]
pub enum polling_status_t {
    POLLING_STATUS_OK = 0,
    POLLING_STATUS_INVALID = 1,
    POLLING_STATUS_UNSUPPORTED = 2,
    POLLING_STATUS_IO = 3,
    POLLING_STATUS_OUT_OF_RANGE = 4,
}

/* polling_t API */

#[no_mangle]
pub unsafe extern "C" fn polling_new(out: *mut *mut polling_t) -> polling_status_t {
    abort_on_panic(|| {
        let poller = match Poller::new() {
            Ok(poller) => poller,
            Err(e) => return convert_error(e),
        };

        let poller = Box::new(poller);
        *out = Box::into_raw(poller) as *mut polling_t;
        polling_status_t::POLLING_STATUS_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_free(poller: *mut polling_t) {
    abort_on_panic(|| {
        let poller = Box::from_raw(poller as *mut Poller);
        drop(poller);
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_add(
    poller: *const polling_t,
    source: raw_source_t,
    event: *const polling_event_t,
    mode: c_int,
) -> polling_status_t {
    abort_on_panic(|| {
        let poller = &*(poller as *const Poller);
        let event = &*(event as *const polling_event_t);

        // Convert the event.
        let event = Event {
            key: event.key,
            readable: event.readable != 0,
            writable: event.writable != 0,
        };

        // Convert the mode.
        let mode = match polling_mode_t::from_int(mode) {
            Some(polling_mode_t::POLLING_MODE_ONESHOT) => PollMode::Oneshot,
            Some(polling_mode_t::POLLING_MODE_LEVEL) => PollMode::Level,
            Some(polling_mode_t::POLLING_MODE_EDGE) => PollMode::Edge,
            None => return polling_status_t::POLLING_STATUS_INVALID,
        };

        match poller.add_with_mode(source, event, mode) {
            Ok(()) => polling_status_t::POLLING_STATUS_OK,
            Err(e) => convert_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_modify(
    poller: *const polling_t,
    source: raw_source_t,
    event: *const polling_event_t,
    mode: c_int,
) -> polling_status_t {
    abort_on_panic(|| {
        let poller = &*(poller as *const Poller);
        let event = &*(event as *const polling_event_t);

        // Convert the event.
        let event = Event {
            key: event.key,
            readable: event.readable != 0,
            writable: event.writable != 0,
        };

        // Convert the mode.
        let mode = match polling_mode_t::from_int(mode) {
            Some(polling_mode_t::POLLING_MODE_ONESHOT) => PollMode::Oneshot,
            Some(polling_mode_t::POLLING_MODE_LEVEL) => PollMode::Level,
            Some(polling_mode_t::POLLING_MODE_EDGE) => PollMode::Edge,
            None => return polling_status_t::POLLING_STATUS_INVALID,
        };

        match poller.modify_with_mode(source, event, mode) {
            Ok(()) => polling_status_t::POLLING_STATUS_OK,
            Err(e) => convert_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_delete(
    poller: *const polling_t,
    source: raw_source_t,
) -> polling_status_t {
    abort_on_panic(|| {
        let poller = &*(poller as *const Poller);
        match poller.delete(source) {
            Ok(()) => polling_status_t::POLLING_STATUS_OK,
            Err(e) => convert_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_wait(
    poller: *const polling_t,
    events: *mut polling_events_t,
    timeout: *const polling_timeout_t,
    num_events: *mut size_t,
) -> polling_status_t {
    abort_on_panic(|| {
        let poller = &*(poller as *const Poller);
        let events = &mut *(events as *mut Vec<Event>);

        // Convert the timeout.
        let timeout = if timeout.is_null() {
            None
        } else {
            let timeout = &*(timeout as *const polling_timeout_t);
            Some(std::time::Duration::new(
                timeout.seconds,
                timeout.nanoseconds,
            ))
        };

        // Wait for events.
        match poller.wait(events, timeout) {
            Ok(count) => {
                *num_events = count;
                polling_status_t::POLLING_STATUS_OK
            }
            Err(e) => convert_error(e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_notify(poller: *const polling_t) -> polling_status_t {
    abort_on_panic(|| {
        let poller = &*(poller as *const Poller);

        match poller.notify() {
            Ok(()) => polling_status_t::POLLING_STATUS_OK,
            Err(e) => convert_error(e),
        }
    })
}

/* polling_events_t API */

#[no_mangle]
pub unsafe extern "C" fn polling_events_new(out: *mut *mut polling_events_t) -> polling_status_t {
    abort_on_panic(|| {
        let events = Box::<Vec<Event>>::default();
        *out = Box::into_raw(events) as *mut polling_events_t;
        polling_status_t::POLLING_STATUS_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_events_with_capacity(
    capacity: size_t,
    out: *mut *mut polling_events_t,
) -> polling_status_t {
    abort_on_panic(|| {
        let events = Box::new(Vec::<Event>::with_capacity(capacity));
        *out = Box::into_raw(events) as *mut polling_events_t;
        polling_status_t::POLLING_STATUS_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_events_free(events: *mut polling_events_t) {
    abort_on_panic(|| {
        let events = Box::from_raw(events as *mut Vec<Event>);
        drop(events);
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_events_len(
    events: *const polling_events_t,
    out: *mut size_t,
) -> polling_status_t {
    abort_on_panic(|| {
        let events = &*(events as *const Vec<Event>);
        *out = events.len();
        polling_status_t::POLLING_STATUS_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_events_get(
    events: *const polling_events_t,
    index: size_t,
    out: *mut polling_event_t,
) -> polling_status_t {
    abort_on_panic(|| {
        let events = &*(events as *const Vec<Event>);
        let event = &mut *(out as *mut polling_event_t);

        if index >= events.len() {
            return polling_status_t::POLLING_STATUS_INVALID;
        }

        let our_event = match events.get(index) {
            Some(event) => event,
            None => return polling_status_t::POLLING_STATUS_OUT_OF_RANGE,
        };

        event.key = our_event.key;
        event.readable = our_event.readable as c_int;
        event.writable = our_event.writable as c_int;
        polling_status_t::POLLING_STATUS_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_events_clear(events: *mut polling_events_t) {
    abort_on_panic(|| {
        let events = &mut *(events as *mut Vec<Event>);
        events.clear();
    })
}

#[no_mangle]
pub unsafe extern "C" fn polling_events_copy(
    events: *const polling_events_t,
    buffer: *mut polling_event_t,
    buffer_len: size_t,
) -> size_t {
    abort_on_panic(|| {
        let events = &*(events as *const Vec<Event>);
        let buffer = std::slice::from_raw_parts_mut(buffer, buffer_len);

        events
            .iter()
            .zip(buffer.iter_mut())
            .map(|(in_event, out_event)| {
                out_event.key = in_event.key;
                out_event.readable = in_event.readable as c_int;
                out_event.writable = in_event.writable as c_int;
            })
            .count() as _
    })
}

/* Helpers */

fn abort_on_panic<R>(f: impl FnOnce() -> R) -> R {
    struct Bomb;

    impl Drop for Bomb {
        fn drop(&mut self) {
            std::process::abort();
        }
    }

    let bomb = Bomb;
    let result = f();
    std::mem::forget(bomb);
    result
}

fn convert_error(e: io::Error) -> polling_status_t {
    match e.kind() {
        io::ErrorKind::InvalidInput => polling_status_t::POLLING_STATUS_INVALID,
        io::ErrorKind::Unsupported => polling_status_t::POLLING_STATUS_UNSUPPORTED,
        _ => polling_status_t::POLLING_STATUS_IO,
    }
}
