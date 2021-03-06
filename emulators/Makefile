###############################################################################
#
# KMC Emulators Root Makefile.
#
# KMC Emulators Root Makefile.
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

SS137DIR=../ss137

COMMON=$(SS137DIR)/common
COMMONINCLUDE=$(COMMON)/include

SS137LIBDIR=$(SS137DIR)/ss137_lib
SS137LIBINCLUDE=$(SS137LIBDIR)/include
SS137SRC=$(SS137LIBDIR)/src
SS137LIB=$(SS137SRC)/libss137.a


TLSWRAPPERDIR=$(SS137DIR)/tls_wrapper
TLSWRAPPERINCLUDE=$(TLSWRAPPERDIR)/include
TLSWRAPPERSRC=$(TLSWRAPPERDIR)/src
TLSWRAPPERLIB=$(TLSWRAPPERSRC)/libtlswrapper.a


GNUTLSINCLUDE=$(shell pkg-config --cflags gnutls)
GNUTLSLIB=$(shell pkg-config --libs gnutls)


INCLUDES=-I$(COMMONINCLUDE) -I$(SS137LIBINCLUDE) 

CFLAGS= -g -Wall -D__DEBUG__ -pedantic -std=c99 $(INCLUDES)
# LIBS=-lssl -lcrypto


BIN1=track-side-entity
BIN2=kmc-core-emulator

ALLBIN=$(BIN1) $(BIN2)

SRCS = $(BIN1).c $(BIN2).c
OBJS = ${SRCS:%.c=%.o}

.PHONY: all clean 

#------------------------------------------------------------------------------

all: $(BIN1) $(BIN2)

$(BIN1): $(BIN1).o  $(SS137LIB) $(TLSWRAPPERLIB)
	$(CC) $(CFLAGS) $< -o $@  $(SS137LIB) $(TLSWRAPPERLIB) $(GNUTLSLIB)

$(BIN2): $(BIN2).o  $(SS137LIB) $(TLSWRAPPERLIB)
	$(CC) $(CFLAGS) $< -o $@  $(SS137LIB) $(TLSWRAPPERLIB) $(GNUTLSLIB)


$(SS137LIB):
	$(MAKE) -C $(SS137SRC) lib

$(TLSWRAPPERLIB):
	$(MAKE) -C $(TLSWRAPPERSRC) lib

clean:
	rm -rf $(OBJS) $(ALLBIN)  *~
