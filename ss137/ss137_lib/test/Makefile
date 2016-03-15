CFLAGS= -g -Wall -pedantic -D__DEBUG__ -std=c99
LIBS=-L/home/pesoli/Downloads/openssl-1.0.1r -lssl -lcrypto -ldl
INCLUDE=-I../include -I../../include -I../../tls_wrapper/include/ -I/usr/include/p11-kit-11
GNUTLSINCLUDE=-I../include -I../../include -I../../tls_wrapper/include/ -I/usr/include/p11-kit-11 -I/home/pesoli/Downloads/gnutls-3.4.9/lib/includes
GNUTLSLIBS=-L/home/pesoli/Downloads/gnutls-3.4.9/lib/.libs -lgnutls -ldl


all:
	gcc $(CFLAGS) $(GNUTLSINCLUDE) ../src/net_utils.c ../src/ss137_lib.c ../../tls_wrapper/src/gnutls_wrapper.c kmc.c $(GNUTLSLIBS) -o kmc
	gcc $(CFLAGS) $(GNUTLSINCLUDE) ../src/net_utils.c ../src/ss137_lib.c ../../tls_wrapper/src/gnutls_wrapper.c track.c $(GNUTLSLIBS) -o track