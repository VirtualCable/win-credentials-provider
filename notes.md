# Environment variables that we can use (system environment)

- `UDSCP_DEBUG`: If set, overrides the logging level to the specified value.
- `UDSCP_ENABLE_FLOW_LOG`: If set to "1", enables flow logging.

# For use in debug builds:
- `UDSCP_FAKE_CREDENTIALS`: If set, returns the specified credentials instead of querying the broker. username:password:domain
- `UDS_FORCE_ACTOR_TOKEN`: If set, forces the use of the specified actor token instead of querying the broker.