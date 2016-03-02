INCLUDE=-I../include -I../../include -I../../tls_wrapper/include/
CFLAGS= -g -Wall -pedantic -D__DEBUG__ -std=c99

all:
	gcc $(CFLAGS) $(INCLUDE) ../src/net_utils.c ../src/ss137_lib.c main.c  -o kmc 