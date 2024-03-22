# Apache module mod_request_limit

### Summary
The `mod_request_limit` module limits the amount of requests a client can make to the server. Is uses a concept of buckets that track requests over a given time, an block the request 
when the limits are exceeded (bucket spills over). You can define multiple buckets, allowing for different limits for different resources. 



## ReqLimitSetNetmask4 Directive
The `ReqLimitSetNetmask4 <bits>` allows you define the number of bits that are used for calculating the subnet mask that will be applied to the client IPv4 address. This allows you to group IPs from the same subnet together.

### Arguments
`bits`
The number of bits to use for the subnetmask. The default value is `32`, effectively treating every IP as unique.
Setting this to `0` would effectively translate every IP to `0.0.0.0`, making every user share the same counter.   

## ReqLimitSetNetmask6 Directive
The `ReqLimitSetNetmask6 <bits>` allows you define the number of bits that are used for calculating the subnet mask that will be applied to the client IPv6 address. This allows you to group IPs from the same subnet together.

### Arguments
`bits`
The number of bits to use for the subnetmask. The default value is `64`, which is the standard IPv6 subnet size as defined by the IETF, and the smallest subnet that can be used locally if auto configuration is used.
Setting this to `0` would effectively translate every IP to `::0`, making every user share the same counter.   
