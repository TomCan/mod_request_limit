# ModReqLimit Change Log

## unversioned changes in main

- added `reportonly` mode through `ReqLimitEngine` directive.

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

## v1.0.0 targets

Following features are targets (or ideas) for the v1.0.0 release, should we ever get there.
- exclude IPs 
- multiple buckets per request
- sliding window/timeframe
- extended block period once triggered
- create .deb packages
- allow the use of custom values (eg. user-agent string) to use as key instead of client IP
