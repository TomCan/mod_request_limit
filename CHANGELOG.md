# ModReqLimit Change Log

## v0.4.0

- changed handler from AP_HOOK_MIDDLE to AP_HOOK_VERY_FIRST to run before mod_proxy/mod_proxy_fcgi
- added ability to exclude IP addresses
  - `ReqLimitAllow`

## v0.3.0

- fixed locations of configuration Directives
- added `reportonly` mode through `ReqLimitEngine` directive.
- added Makefile for build and package

## v0.2.0

- added ability to apply mask on client IP (impose limits on subnet rather than single IP)
  - `ReqLimitSetNetmask4` and `ReqLimitSetNetmask6`
- added custom status code when blocking
  - `ReqLimitHTTPStatus`
- added documentation for all existing configuration directives
- improved validation of configuration directive arguments

## v0.1.0

Basic functionality, first "working" version.
- added Change Log
- added current state of WIP
- updated README

## Future targets

Following features are targets or ideas for future releases. Considder it a non-binding TODO-list.
- multiple buckets per request
- sliding window/timeframe
- extended block period once triggered
- create .deb packages
- allow the use of custom values (eg. user-agent string) to use as key instead of client IP
