build: apxs -i -a -c mod_request_limit.c

package-deb:
	rm -rf package/tmp && mkdir package/tmp
	cp -r package/deb/* package/tmp
	cp .libs/mod_request_limit.so package/tmp/usr/lib/apache2/modules
	dpkg-deb --build package/tmp
