# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- ## Unreleased -->

## [1.7.3](https://github.com/unioslo/mreg-cli/releases/tag/1.7.3) - 2025-11-18

### Changed

- No longer requires a writable log file to start the application. In extreme cases where no writable log file directory can be found, logging will be disabled.

### Fixed

- Temporary file creation failing due to non-unique filename in `/tmp` directory. Now creates a unique temporary directory for the temporary file.

## [1.7.2](https://github.com/unioslo/mreg-cli/releases/tag/1.7.2) - 2025-11-17

### Fixed

- `uv.lock` file missing `rich` dependency.

## [1.7.1](https://github.com/unioslo/mreg-cli/releases/tag/1.7.1) - 2025-11-17

### Fixed

- Missing `rich` dependency in `pyproject.toml`.

## [1.7.0](https://github.com/unioslo/mreg-cli/releases/tag/1.7.0) - 2025-11-14

### Added

- `policy list_hosts -exclude EXCLUDEROLE [EXCLUDEROLE ...]` option to exclude hosts that have the given role(s) when listing hosts with a role. Supports multiple arguments and regular expressions.
- Environment variable support for all config file options.
  - Environment variables are prefixed with `MREG_CLI_` and use uppercase letters and underscores instead of lowercase letters and hyphens.
  - For example, the `http_timeout` config file option can be set with the `MREG_CLI_HTTP_TIMEOUT` environment variable.
  - Environment variables take precedence over config file options.
  - All config file options and their corresponding environment vaiables:

| Config  FIle                         | Env                                     |
|----------------------------------|-----------------------------------------|
| `url`                            | `MREG_CLI_URL`                         |
| `user`                           | `MREG_CLI_USER`                        |
| `domain`                        | `MREG_CLI_DOMAIN`                     |
| `timeout`                   | `MREG_CLI_TIMEOUT`                 |
| `prompt`                   | `MREG_CLI_PROMPT`                 |
| `category_tags`                   | `MREG_CLI_CATEGORY_TAGS`                 |
| `location_tags`                   | `MREG_CLI_LOCATION_TAGS`                 |
| `cache`                           | `MREG_CLI_CACHE`                          |
| `cache_ttl`                   | `MREG_CLI_CACHE_TTL`                 |
| `http_timeout`                   | `MREG_CLI_HTTP_TIMEOUT`                 |
| `record_traffic`                 | `MREG_CLI_RECORD_TRAFFIC`               |
| `record_traffic_without_timestamps` | `MREG_CLI_RECORD_TRAFFIC_WITHOUT_TIMESTAMPS` |
| `token_only`                     | `MREG_CLI_TOKEN_ONLY`                   |
| `source`                         | `MREG_CLI_SOURCE`                       |
| `verbose`                        | `MREG_CLI_VERBOSE`                      |
| `log_file`                      | `MREG_CLI_LOG_FILE`                     |
| `log_level`                      | `MREG_CLI_LOG_LEVEL`                    |

- _New_ configuration options, previously only available as CLI options, exposed as both config file options and environment variables:

| Config File                           | Env                                     |
|----------------------------------|-----------------------------------------|
| `http_timeout`                   | `MREG_CLI_HTTP_TIMEOUT`                 |
| `record_traffic`                 | `MREG_CLI_RECORD_TRAFFIC`               |
| `record_traffic_without_timestamps` | `MREG_CLI_RECORD_TRAFFIC_WITHOUT_TIMESTAMPS` |
| `token_only`                     | `MREG_CLI_TOKEN_ONLY`                   |
| `source`                         | `MREG_CLI_SOURCE`                       |
| `verbose`                        | `MREG_CLI_VERBOSE`                      |
| `log_file`\*                      | `MREG_CLI_LOG_FILE`                     |
| `log_level`                      | `MREG_CLI_LOG_LEVEL`                    |

\*: The old name `logfile` is deprecated, but remains a valid alias for this field.

### Changed

- Default config file location is now `$XDG_CONFIG_HOME/mreg-cli/mreg-cli.conf` (was `~/.config/mreg-cli.conf`).
  - The old config file location remains supported for backwards compatibility, but will be removed in a future release.
- `help configuration` now shows environment variables.
- `logging start` no longer toggles logging on and off. Now aborts if logging is already enabled.
- `logging stop` now aborts if logging is not enabled.
- `logging status` now shows if logging is enabled or not.

## [1.6.0](https://github.com/unioslo/mreg-cli/releases/tag/1.6.0) - 2025-10-13

### Added

- `network find -host <hostname>` option to search for networks with IPs assigned to the given host.

### Fixed

- `network community_remove_host` command not utilizing the `-ip` argument to disambiguate between networks when multiple networks have the same community name.
- `policy host_add` terminating prematurely when using multiple hosts and one of them is already a member of the policy.

## [1.5.1](https://github.com/unioslo/mreg-cli/releases/tag/1.5.1) - 2025-09-26

### Fixed

- `network policy_set_prefix` and `network policy_unset_prefix` commands not working due to a typo in the field name.

## [1.5.0](https://github.com/unioslo/mreg-cli/releases/tag/1.5.0) - 2025-09-01

### Added

- `help health` command for checking the health of the server. The command will display "Unknown" for fields that are not implemented on the server.
- Caching of API responses. Enabled by default. Configurable:
  - Enable/disable caching (default: `true`)
    - Config file: `cache=true|false`
    - CLI: `--no-cache` (flag)
  - Cache time-to-live (TTL) in seconds (default: `300`)
    - Config file: `cache_ttl=<seconds>`
    - CLI: `--cache-ttl <seconds>`

## [1.4.2](https://github.com/unioslo/mreg-cli/releases/tag/1.4.2) - 2025-08-15

### Fixed

- `host info` for hosts with A(AAA)-records that point to networks not managed by MREG.
- `network community_host_add` raising a 404 error for hosts with IPs in networks not managed by MREG.

## [1.4.1](https://github.com/unioslo/mreg-cli/releases/tag/1.4.1) - 2025-08-06

### Changed

- `ptr add -force` now allows adding PTR records for IPs that are not in a network managed by MREG.

## [1.4.0](https://github.com/unioslo/mreg-cli/releases/tag/1.4.0) - 2025-06-20

### Added

- Configurable HTTP request timeout. The timeout can be set with the `--timeout` option or with the `timeout` option in the config file.

### Changed

- Require `-force` for `host {a,aaaa}_remove` if the argument is a CNAME.
- Require `-force` when using network or broadcast addresses as arguments for the following commands:
  - `host add`
  - `host a_add`
  - `host aaaa_add`
  - `host a_change`
  - `host aaaa_change`

### Fixed

- `host info <ip>` command not working for IP addresses associated with multiple hosts.

## [1.3.0](https://github.com/unioslo/mreg-cli/releases/tag/1.3.0) - 2025-05-20

### Added

- Network policy commands:
  - `network policy_add`
  - `network policy_create`
  - `network policy_delete`
  - `network policy_info`
  - `network policy_list`
  - `network policy_rename`
  - `network policy_remove`
  - `network policy_set_description`
  - `network policy_set_prefix`
  - `network policy_unset_prefix`
  - `network policy_attribute_add`
  - `network policy_attribute_create`
  - `network policy_attribute_delete`
  - `network policy_attribute_info`
  - `network policy_attribute_list`
  - `network policy_attribute_remove`
  - `network policy_attribute_set_description`
  - `network community_create`
  - `network community_delete`
  - `network community_info`
  - `network community_list`
  - `network community_rename`
  - `network community_set_description`
  - `network community_host_add`
  - `network community_host_remove`
- `network create -policy` option for specifying the policy of the network to create.
- Error handling for DRF errors.
- Handling of 404 errors that do not contain a JSON payload.

## [1.2.4](https://github.com/unioslo/mreg-cli/releases/tag/1.2.4) - 2025-01-30

### Fixed

- Reverse zone management was completely broken. This affected all zone-related commands when using reverse zones.

## [1.2.3](https://github.com/unioslo/mreg-cli/releases/tag/1.2.3) - 2024-12-16

### Added

- `a_add` & `aaaa_add` `-force` option to force use an IP from a network that cannot be found in MREG.

### Fixed

- Commands that try to find networks by IP raising a 404 error instead of a proper error message when no network can be found with the given IP.

## [1.2.2](https://github.com/unioslo/mreg-cli/releases/tag/1.2.2) - 2024-12-09

### Fixed

- `dhcp assoc` and `host add` commands displaying unique constraint error instead of a proper error message when a MAC is already associated with an IP.
- Validation errors causing the application to crash instead of displaying a proper error message.

## [1.2.1](https://github.com/unioslo/mreg-cli/releases/tag/1.2.1) - 2024-12-02

### Fixed

- Host lookup with IPv6 addresses raising `ValidationError` when no host can be found with the given address.

### Removed

- Support for fetching hosts that have a valid IP/MAC address as their hostname.

## [1.2.0](https://github.com/unioslo/mreg-cli/releases/tag/1.2.0) - 2024-11-25

### Added

- Support for `help versions` which shows versions of the CLI and the server for servers that have implemented the `/meta/version` (and `/meta/libraries` endpoints for superusers).
- Support for `help whoami` which shows information about the current user as the server sees them. This includes the username, attributes, groups, and permissions. This command is only available if the server has implemented the `/meta/users` endpoint.
- Support for `help whois <username>` which allows elevated users to see information about the given user. Also requires the `/meta/users` endpoint to be implemented on the server.

### Fixed

- REPL command completion not showing descriptions for commands.
- `host info` with MAC address argument not working for hosts with multiple IPs associated with the same MAC address.
- Failed token file write causing the application to crash.
- Connection strings without domains and with ports are now parsed properly for prompt interpolation.

## [1.1.0](https://github.com/unioslo/mreg-cli/releases/tag/1.1.0) - 2024-11-19

### Added

- Customizable prompt with string interpolation. The prompt can be customized with the `--prompt` option or with the `prompt` option in the config. The prompt can be customized with the following variables:
  - `{user}`: Username of active user
  - `{proto}`: Protocol part of the server URL
  - `{host}`: Host/domain name part of the server URL
  - `{port}`: Port part of the server URL (if any)
  - `{domain}`: Domain name. Defaults to `uio.no` if not specified.
    Uses the domain specified with `--domain` or the `domain` option in the config.

### Fixed

- MAC adress validation. Now supports all common formats. See the [Pydantic docs](https://docs.pydantic.dev/latest/api/pydantic_extra_types_mac_address/) for more information.
- `host add`: Re-introduced support for network/IP ending with `/`.
  - Automatically deduces the correct network to assign an IP from.
- `host add`: No longer possible to assign network address (first address of subnet) or broadcast address (last address of subnet) to a host.

## [1.0.1](https://github.com/unioslo/mreg-cli/releases/tag/1.0.1) - 2024-10-21

### Fixed

- Rendering of top level command autocompletion in REPL.
- `OK:` messages not being displayed outside of `--record` mode

## [1.0.0](https://github.com/unioslo/mreg-cli/releases/tag/1.0.0) - 2024-10-12

The big Pydantic update. The entire codebase has been rewritten to use Pydantic for request and response validation. This brings with it a huge improvement to the development experience and the robustness of the code.

### Added

- `--version` option to display current application version and exit.
    Version number is in the form of `major.minor.patch` if installed from a published version.
    Shows a version number including the commit hash if installed from a git repository in the form of `major.minor.patch.dev123+gabc1234`.
    See [Default versioning scheme](https://setuptools-scm.readthedocs.io/en/latest/usage/#default-versioning-scheme) in the [setuptools_scm](https://github.com/pypa/setuptools_scm/) documentation for more information.
  - The version can be accessed programmatically with `mreg_cli.__version__`.
- `label set_description` command to set the description of a label.
- `network list_excluded_ranges` command to list the excluded ranges of a network.
- Application can now store tokens for multiple servers and will pick the correct one based on the server URL.
- Building binaries for Windows, Linux and MacOS, and publishing the package to PyPI on each GitHub release.

### Changed

- The application now uses Pydantic internally to validate request and response data. This should make the code more robust and easier to maintain.
- Application now attempts to send JSON for every request. This should improve the consistency of the API responses.
- Version now follows Semantic Versioning 2.0.0 and is automatically determined based on the most recent git tag (`mreg-cli-v*`). As part of this change, the verison has been bumped from 0.9.10 to 1.0.0. See the Added section for more information on how version numbers are accessed.

### Removed

- `label rename -desc` option. Description modification is now done through the new `label set_description` command.

### Fixed

- Hopefully more than we broke.
