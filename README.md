# ModReqLimit
mod_request_limit (ModReqLimit for short) is an modules for the Apache 2.4 httpd server. It allows server admins to
limit the number of requests originating from a single ip or subnet. Different limits can be set based on Server, Directory, 
Location/LocationMatch or Files/FilesMatch directives.

## How to build

```
apt-get install apache2 apache2-dev
apxs -i -a -c mod_request_limit.c
```

## Configuration
The concept is that you create 'buckets' that will receive the requests. On a bucket, you will define how many
requests are allowed in what timeframe.
```
<VirtualHost>
...
ReqLimitBucket <bucketname> <requests> <timespan-in-seconds>
# Create bucket named mywebsite, that allows 10 requests in 1 second
ReqLimitBucket mywebsite 10 1
# Create bucket named mylogin, that only allows 1 requests in 1 second
ReqLimitBucket mylogin 1 1
...
</VirtualHost>
```
The period/timespan is in a very simple way. When a request is received, a count is added to the bucket for the IP.
When the time passed since the last bucket clear exceeds the defined timespan, the bucket will be cleared at the start
of the next request for that bucket. This means that in reality, it's possible to exceed the actual number of requests
within a timespan due to overlapping periods. 10 requests in the last 100ms of 1 second window, followed by 10 requests
in the first 100ms of the new 1 second window will effectively result in 20 requests in a 200ms timeframe. It's not
a sliding windows, it's just a counter that resets to 0. For this reason, it's advised to keep the timespans short.

Once a bucket is created, you can assign requests to that bucket from Directory of Location directives
```
<Directory /var/www/html>
    ReqLimitSetBucket mywebsite
</Directory>

<Location /login.php>
    ReqLimitSetBucket mylogin
</Location>
```

You can also disable the module for specific paths using `ReqLimitEngine`
```
<Location /assets>
    ReqLimitEngine off
</Location>
```

For more configuration options, [see the docs](docs/mod_request_limit.md).