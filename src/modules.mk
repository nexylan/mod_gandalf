#mod_gandalf.la: mod_gandalf.slo
mod_gandalf.la: $(shell ls -1 *.c | awk -F'.' '{printf("%s.slo ", $$1);}') 
	$(SH_LINK) $(LIBS) -rpath $(libexecdir) -module -avoid-version  $(shell ls -1 *.c | awk -F'.' '{printf("%s.lo ", $$1);}')
DISTCLEAN_TARGETS = modules.mk
shared =  mod_gandalf.la
