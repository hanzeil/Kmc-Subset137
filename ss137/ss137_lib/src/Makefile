###############################################################################
#
# KMC SS137LIB Root Makefile.
#
# KMC SS137LIB Root Makefile.
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

TLSWRAPPERDIR=../../tls_wrapper
TLSWRAPPERINCLUDE=$(TLSWRAPPERDIR)/include

COMMON=../../common
COMMONINCLUDE=$(COMMON)/include


INCLUDES=-I../include -I$(COMMONINCLUDE) -I$(TLSWRAPPERINCLUDE)

CFLAGS= -g -Wall -D__DEBUG__ -pedantic -std=c99 $(INCLUDES)

LIBNAME=libss137.a

SRCS=ss137_lib.c net_utils.c
OBJS=ss137_lib.o net_utils.o

.PHONY: clean 

#------------------------------------------------------------------------------

lib: $(LIBNAME)

$(LIBNAME): $(OBJS)
	$(AR) rs $(LIBNAME) $(OBJS)


clean:
	rm -rf $(OBJS) $(LIBNAME) *~
