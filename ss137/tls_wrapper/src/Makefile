###############################################################################
#
# KMC SS137 TLS-Wrapper Makefile.
#
# KMC SS137 TLS-Wrapper Makefile.
#
# @file: ./Makefile
# $Author: $
# $Revision: $
# $Date: $
#
# History:
#
# Version     Date      Author         Change Description
#
# - $Id: $  
#
###############################################################################

COMMON=../../common
COMMONINCLUDE=$(COMMON)/include

INCLUDES=-I../include -I$(COMMONINCLUDE)

CFLAGS= -g -Wall -D__DEBUG__ -pedantic -std=c99 $(INCLUDES)

LIBNAME=libtlswrapper.a

# SRCS=openssl_wrapper.c
# OBJS=openssl_wrapper.c
SRCS=gnutls_wrapper.c 
OBJS=gnutls_wrapper.o 

.PHONY: clean 

#------------------------------------------------------------------------------



lib: $(LIBNAME)

$(LIBNAME): $(OBJS)
	$(AR) rs $(LIBNAME) $(OBJS)


clean:
	rm -rf $(OBJS) $(LIBNAME) *~
