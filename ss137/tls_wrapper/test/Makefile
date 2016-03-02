INCLUDE=-I../include -I../../include -I../../openssl/distribution/include/
CFLAGS= -g -Wall -pedantic -D__DEBUG__ -std=c99
LDFLAGS=-L../../openssl/distribution/lib/
LIBS=-lssl -lcrypto -ldl

test: clean tls_client tls_server

tls_client:
	gcc $(CFLAGS) $(LDFLAGS) $(INCLUDE) -o tls_client tls_client.c ../src/tls_wrapper.c $(LIBS)

tls_server:
	gcc $(CFLAGS) $(LDFLAGS) $(INCLUDE) -o tls_server tls_server.c ../src/tls_wrapper.c $(LIBS)

clean:
	rm -rf tls_client tls_server

