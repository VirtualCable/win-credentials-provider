# Environment variables that we can use (system environment)

- `UDSCP_DEBUG`: If set, overrides the logging level to the specified value.
- `UDSCP_FORCE_RDP`: If set to "1", treats the session as an RDP session ALWAYS. Only for testing.
- `UDSCP_ENABLE_FLOW_LOG`: If set to "1", enables flow logging.

# For use in debug builds:
- `UDSCP_FAKE_CREDENTIALS`: If set, returns the specified credentials instead of querying the broker. username:password:domain

