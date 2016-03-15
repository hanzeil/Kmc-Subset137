###############################################################################
#
# KMC SS137 Library Makefile.
#
# KMC SS137 Library Makefile.
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


LIBS		= ss137_lib tls_wrapper
DOCS		= docs

ALLTARGETS	= $(LIBS)

.PHONY: all docs clean 

#------------------------------------------------------------------------------

all:
	@for sub_dir in $(ALLTARGETS); \
	  do $(MAKE)  -C $$sub_dir/src || exit $$? ; \
	done

docs:
	cd $(DOCS) ; \
	doxygen

clean:
	@rm -f *~ ; \
	cd $(DOCS) ; rm -rf html ; cd - ; \
	for sub_dir in $(ALLTARGETS); do \
	  $(MAKE) -C $$sub_dir/src  clean ; \
	done
