# ModReqLimit
Because mod_ratelimit was already taken... ;) 

# WIP ALERT WIP ALERT WIP ALERT
Yes, still very much WIP. Expect things to change, break or be abandonned.

## How to build

```
apt-get install apache2 apache2-dev
apxs -i -a -c mod_request_limit.c
```

## Configuration
The idea (can change) is to create 'buckets' that will receive the requests. On a bucket, you will define how many requests are allowed in what timeframe.
```
<VirtualHost>
...
# Create bucket named mywebsite, that allows 10 requests in 1 second
ReqLimitBucket mywebsite 10 1
# Create bucket named mylogin, that only allows 1 requests in 1 second
ReqLimitBucket mylogin 1 1
...
</VirtualHost>
```

Once a bucket is created, you can assign requests to that bucket from Directory of Location directives
```
<Directory /var/www/html>
    ReqLimitUseBucket mywebsite
</Directory>

<Location /login.php>
    ReqLimitUseBucket mylogin
</Location>
```

You can also disable the module for specific paths using `ReqLimitEngine`
```
<Location /assets>
    ReqLimitEngine off
</Location>
```
