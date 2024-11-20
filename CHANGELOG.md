# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- ## [Unreleased] -->

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

- `host add`: Re-introduced support for network/ip ending with `/`.
  - Automatically deduces the correct network to assign an IP from.
- `host add`: No longer possible to assign the network ID (first address of subnet) to a host.

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
