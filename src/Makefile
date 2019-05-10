## Makefile to compile mod_gandalf Apache Module

## Comment this or set 0 to disable HTTPS support
ifndef DISABLE_SSL
    HTTPS:=1
else
    HTTPS:=0
endif
ifneq (,$(APACHE_BUILD_PATH))
    APXS_PATH:=$(APACHE_BUILD_PATH)/bin/
endif
ifeq (,$(shell which $(APXS_PATH)apxs 2>/dev/null))
    ifeq (,$(shell which $(APXS_PATH)apxs2  2>/dev/null))
        $(error "Neither apxs nor apxs2 found. For custom path, please provide Apache path ex: "make prepare APACHE_BUILD_PATH=/opt/apachepath")
    else
        APXS=$(APXS_PATH)apxs2
    endif
else
    APXS=$(APXS_PATH)apxs
endif
TMP_DIR := /tmp/$(shell date +%s).$(shell echo $$RANDOM)
$(shell mkdir -p $(TMP_DIR) && cd $(TMP_DIR) && $(APXS) -n test -g''>/dev/null 2>&1)
TMP_MK_FILE := $(TMP_DIR)/test/Makefile
OS=$(shell if grep -q -i SuSE /etc/*release; then echo SuSE; fi)
ifeq ($(strip $(OS)),)
    OS=$(shell if grep -q -i Gentoo /etc/*release; then echo Gentoo; fi)
endif
UNAME=$(shell uname)

builddir=.
ifeq ($(OS),$(filter $(OS), SuSE Gentoo))
    include_file_path=$(shell awk '/^include/{print $$2}' $(TMP_MK_FILE))
    include_file_dir=$(shell dirname $(include_file_path))
    top_srcdir=$(shell dirname $(include_file_dir))
    top_builddir=$(shell dirname $(include_file_dir))
else
    top_srcdir=$(shell awk -F'=' '/^top_srcdir=/{print $$2}' $(TMP_MK_FILE))
    #top_builddir=$(shell awk -F'=' '/^top_builddir=/{print $$2}' $(TMP_MK_FILE))
    top_builddir := /usr/lib64/apache2
endif
include $(shell awk '/^include/{print $$2}' $(TMP_MK_FILE))

# the used tools
APACHECTL=apachectl

DOME_CFLAGS=-Wc,-Wall -Wc,-Wimplicit-function-declaration -DPRE_INIT_CONNECTION

# additional defines, includes and libraries
DEFS=-DWITH_HTTPD $(DOME_CFLAGS)
LIBS=-lpthread
ifneq ($(UNAME),Darwin)
LIBS+=-lrt
endif

ifeq ($(HTTPS),1)
DEFS+=-DENABLE_HTTPS
LIBS+=-lssl -lcrypto
ifeq ($(UNAME),Darwin)
DEFS+=-I /usr/local/opt/openssl/include
LIBS+=-L/usr/local/opt/openssl/lib
endif
endif

prepare_dome:
	-find include/*.c -type f | while read fname; do ln -sf $$fname `basename $$fname`; done
	-find include/*.h -type f | while read fname; do ln -sf $$fname `basename $$fname`; done

clean_dome:
	-rm -rf `find . -type l`

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean: clean_dome
	-rm -f mod_gandalf.o mod_gandalf.lo mod_gandalf.slo mod_gandalf.la 

#  Prepare for compilation
prepare: prepare_dome

#   the default target
all: local-shared-build

#   simple test
test: reload
	lynx -mime_header http://localhost/datadome_shiled

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

coucou:
	echo "LoadModule mod_gandalf modules/mod_gandalf.so" >> $(shell dirname $(shell dirname $(shell which "$(APXS)")))/conf/httpd.conf