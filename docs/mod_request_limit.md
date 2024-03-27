# Apache module mod_request_limit

### Summary
The `mod_request_limit` module limits the amount of requests a client can make to the server. It uses a concept of
buckets that track requests over a given time, and block the request when the limits are exceeded (bucket spills over).
You can define multiple buckets, allowing for different limits for different resources. 

## Logging
The `mod_request_limit` module logs block events as error, while most other information is logged at debug level.
When troubleshooting, set the LogLevel of `debug` or `trace1`. 

## ReqLimitEngine Directive
The `ReqLimitEngine mode` directive enables of disables the processing of the requests by the request limiting engine.
This can be useful in different context. For example, you could disable the engine in a Directory of Location that
serves static assets. You could also apply a different bucket with higher limits, but processing of such requests 
would require more CPU and memory as opposed to just disabling the engine.

### Arguments
`mode`  
When set to `off`, the engine is disabled and will not process or count the requests. This is the default value.  
When set to `on`, the engine is enabled and will perform counting of requests. When a requests exceeds the
limit, it will be blocked.  
When set to `reportonly`, the engine is behave like in `on` mode, with the exception that will not block any requests.
It will simple report any would-be blocks in the error log. This can be used to assess the impact of the module and/or
configuration without actually impacting traffic. 

```
<Directory /var/www/html>
    ReqLimitEngine on
    ReqLimitSetBucket mybucket
</Directory>

<Directory /var/www/html/assets>
    ReqLimitEngine off
</Directory>
```

## ReqLimitBucket Directive
The `ReqLimitBucket name requests timespan` creates a new bucket that can be used to assign requests to.

### Arguments
`name`  
The name of the bucket. This name is used to reffer to by the `ReqLimitSetBucket` directive. 
It should be unique within the server context it is defined in. You can create multiple buckets with
different parameters within the same server context.

`requests`  
The number of requests that are allowed within the timespan defined by the `timespan` argument.
If the number of actual requests exceeds this value, the request will be denied.

`timespan`  
The timespan in seconds that the `requests` limit applies to.

```
<VirtualHost>
    # allow 10 requests every 1 second
    ReqLimitBucket mybucket 10 1
    # allow only 5 requests every 2 seconds
    ReqLimitBucket slowpoke 5 2
</VirtualHost>
```

## ReqLimitSetBucket Directive
The `ReqLimitSetBucket bucket` directive defines the bucket that is used within the given context.
Reffering to different buckets within different contexts will impose seperate limits for those contexts. 

### Arguments
`name`  
The name of the bucket created by the `ReqLimitBucket` directive. Note that the bucket needs to have been defined
in the configuration before you can assign it using the `ReqLimitUseBucket` directive.

### Considderations
Take the following example:
```
<Directory /var/www>
    ReqLimitSetBucket mybucket
</Directory>

<Location /login>
    ReqLimitSetBucket slowpoke
</Location>
<Location /register>
    ReqLimitSetBucket slowpoke
</Location>
```

Contexts that refer to the same bucket, will share the count across the contexts.  
If 2 requests are made to `/login` and 1 request is made to `/register`, the count in the `slowpoke` bucket is 3.

Only one bucket is used. If you have overlapping contexts with different buckets, only the most recent
(based on the merging order of Apache configuration directives) will be used.  
If 2 requests are made to `/login`, the count in the `slowpoke` bucket is 2, but the count in `mybucket` remains 0.

## ReqLimitSetNetmask4 Directive
The `ReqLimitSetNetmask4 bits` directive allows you define the number of bits that are used for calculating the
subnet mask that will be applied to the client IPv4 address. This allows you to group IPs from the same subnet together.

### Arguments
`bits`  
The number of bits to use for the subnetmask. The default value is `32`, effectively treating every IP as unique.
Setting this to `0` would effectively translate every IP to `0.0.0.0`, making every user share the same counter.   

## ReqLimitSetNetmask6 Directive
The `ReqLimitSetNetmask6 bits` directive allows you define the number of bits that are used for calculating the
subnet mask that will be applied to the client IPv6 address. This allows you to group IPs from the same subnet together.

### Arguments
`bits`  
The number of bits to use for the subnetmask. The default value is `64`, which is the standard IPv6 subnet size
as defined by the IETF, and the smallest subnet that can be used locally if auto configuration is used.
Setting this to `0` would effectively translate every IP to `::0`, making every user share the same counter.   

## ReqLimitHTTPStatus Directive
The `ReqLimitHTTPStatus status` directive defines the HTTP status code that is returned when a request is denied.

### Arguments
`status`  
The HTTP status code that is returned. This can be any number between `100` and `999`, although Apache might
return a `500` (internal server error) when an unknown status code is used.
The default value is `429` (too many requests), but `503` (service unavailable) or `403` (forbidden) are also
good candidates when using clients that don't handle `429` correct.

## ReqLimitAllow Directive
The `ReqLimitAllow ip` directive allows you to define IP addresses or subnets that are always allowed. You can repeat
this directive to add multiple allowed IP addresses. If the client IP address matches one of the allowed ips in that
context, processing is stopped for that request.

### Arguments
`ip`  
The IP address or subnet (CIDR notation) to be added to the allow list. 
