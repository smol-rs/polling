//! Emulate level triggered polling using the `polling` crate.
//!
//! `polling` is built to use oneshot mode polling. This means that, once an event is received by the poller,
//! interest in the source is cleared and must be re-registered. It is possible to also poll in level triggered
//! mode, where this interest clearing does not happen and interest in the source remains. However, certain
//! platforms do not support level triggered mode.
//!
//! At the time of write, the only platforms that don't support level triggered polling is Solaris and illumos.
//!
//! Level triggered polling can be emulated by re-registering interest in the source after an event from that
//! source is received. This file describes how this might work as a theoretical level-triggered wrapper around
//! the `Poller` API.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::{collections::HashMap, time::Duration};

use polling::{Event, PollMode};

#[cfg(unix)]
type Raw = std::os::unix::io::RawFd;
#[cfg(windows)]
type Raw = std::os::windows::io::RawSocket;

/// The level-triggered poller.
pub struct Poller {
    /// The inner poller.
    poller: polling::Poller,

    /// The map between registered sources and their modes.
    ///
    /// This is set to `None` if the poller supports level-triggered sources natively.
    sources: Option<Mutex<HashMap<usize, (Raw, Event)>>>,
}

impl Poller {
    /// Create a new poller.
    pub fn new() -> io::Result<Self> {
        let poller = polling::Poller::new()?;

        Ok(Self {
            sources: if poller.supports_level() {
                // We support level triggered polling natively.
                None
            } else {
                // We need to emulate level triggered mode using oneshot mode.
                Some(Mutex::new(HashMap::new()))
            },
            poller,
        })
    }

    /// Add a source to this poller.
    pub fn add(&self, source: Raw, event: Event) -> io::Result<()> {
        if let Some(sources) = &self.sources {
            // Register in oneshot mode and put it in our source map.
            sources.lock().unwrap().insert(event.key, (source, event));
            self.poller.add(source, event)
        } else {
            // Register in level triggered mode.
            self.poller.add_with_mode(source, event, PollMode::Level)
        }
    }

    /// Modify a source in this poller to use a different interest.
    pub fn modify(&self, source: Raw, event: Event) -> io::Result<()> {
        if let Some(sources) = &self.sources {
            // Update our map.
            let mut sources = sources.lock().unwrap();
            let entry: &mut (u64, Event) = sources
                .get_mut(&event.key)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "source not registered"))?;
            entry.0 = source;
            entry.1 = event;

            // Modify oneshot mode.
            self.poller.modify(source, event)
        } else {
            // Modify in level triggered mode.
            self.poller.modify_with_mode(source, event, PollMode::Level)
        }
    }

    /// Delete a source from this poller.
    pub fn delete(&self, source: Raw) -> io::Result<()> {
        self.poller.delete(source)?;

        if let Some(sources) = &self.sources {
            sources.lock().unwrap().retain(|_, (raw, _)| source != *raw);
        }

        Ok(())
    }

    /// Wait for new events.
    pub fn wait(&self, events: &mut Vec<Event>, timeout: Option<Duration>) -> io::Result<usize> {
        let old_len = events.len();
        let count = self.poller.wait(events, timeout)?;

        // Re-register events if we need them.
        if let Some(sources) = &self.sources {
            let sources = sources.lock().unwrap();
            for &ev in &events[old_len..] {
                if let Some((raw, event)) = sources.get(&ev.key) {
                    // Re-register in oneshot mode.
                    self.poller.modify(*raw, *event)?;
                }
            }
        }

        Ok(count)
    }

    /// Notify the poller.
    pub fn notify(&self) -> io::Result<()> {
        self.poller.notify()
    }
}

fn main() -> io::Result<()> {
    // Create a new poller.
    let poller = Poller::new()?;

    // Create a source and register it.
    let (mut reader, mut writer) = tcp_pair().unwrap();
    let reader_token = 1;

    todo!()
}

fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let a = TcpStream::connect(listener.local_addr()?)?;
    let (b, _) = listener.accept()?;
    Ok((a, b))
}
