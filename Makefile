
LIBS		= ss137
KMCCORE		= kmc-core
EMULATORS	= emulators

ALLTARGETS	= $(LIBS) $(KMCCORE) $(EMULATORS) 

.PHONY: all docs clean 

#------------------------------------------------------------------------------

all:
	@for sub_dir in $(ALLTARGETS); \
	  do $(MAKE)  -C $$sub_dir || exit $$? ; \
	done

docs:
	@for sub_dir in $(LIBS); \
	  do $(MAKE)  -C $$sub_dir docs || exit $$? ; \
	done

clean:
	@rm -rf *~ ; \
	for sub_dir in $(ALLTARGETS); do \
	  $(MAKE) -C $$sub_dir  clean ; \
	done
