INCLUDE=-I../include -I../../include -I../../tls_wrapper/include/ -I/usr/include/p11-kit-11 
CFLAGS= -g -Wall -pedantic -D__DEBUG__ -std=c99
LIBS=-lssl -lcrypto -ldl
GNUTLSLIBS=-lgnutls -ldl

all:
	gcc $(CFLAGS) -DKMC $(INCLUDE) ../src/net_utils.c ../src/ss137_lib.c ../../tls_wrapper/src/openssl_wrapper.c kmc.c $(LIBS) -o kmc
	gcc $(CFLAGS) $(INCLUDE) ../src/net_utils.c ../src/ss137_lib.c ../../tls_wrapper/src/openssl_wrapper.c  track.c $(LIBS) -o track