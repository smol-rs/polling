# Version 0.1.7

- Specify oneshot mode in epoll/wepoll at insert.

# Version 0.1.6

- Add logging.

# Version 0.1.5

- Fix a bug where epoll would block when the timeout is set to zero.
- More tests.

# Version 0.1.4

- Optimize notifications.
- Fix a bug in timeouts on Windows where it would trigger too early.
- Support sub-nanosecond precision on Linux/Android.

# Version 0.1.3

- Improve error handling around event ports fcntl

# Version 0.1.2

- Add support for event ports (illumos and Solaris)

# Version 0.1.1

- Improve documentation
- Fix a bug in `Event::none()`.

# Version 0.1.0

- Initial version
