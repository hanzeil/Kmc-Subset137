######################################################################
######################################################################

LIBS		= ss137_lib tls_wrapper

ALLTARGETS	= $(LIBS)

.PHONY: all clean 

#------------------------------------------------------------------------------

all:
	@for sub_dir in $(ALLTARGETS); \
	  do $(MAKE)  -C $$sub_dir/src || exit $$? ; \
	done

clean:
	@rm -f *~ ; \
	for sub_dir in $(ALLTARGETS); do \
	  $(MAKE) -C $$sub_dir/src  clean ; \
	done
