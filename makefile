-include makefile.vars

all: sstpd/codec$(EXT_SUFFIX)
clean:; rm -vf sstpd/codec.*.so makefile.vars
test:; @echo CONF="$(CONFIG_ARGS)" -- $(value COVERAGE_REPORT_OPTIONS) -- $(MULTIARCH_CPPFLAGS) -- $(lastword $(MAKEFILE_LIST)) $(MAKE_RESTARTS)

vars2 = $(foreach v, $(filter-out .VARIABLES vars, $(.VARIABLES)), \
    $(if $(filter-out environment, $(origin $(v))),                \
        $(info [$(origin $(v))] $(v)=$(value $(v)))                \
    )                                                              \
)
info:; $(vars2)

.EXTRA_PREREQS = $(MAKEFILE_LIST)
%: %.c; $(CC) -Wall -Wextra -O0 -g -o $@ $^

makefile.vars: $(filter-out makefile.vars,$(MAKEFILE_LIST))
	python3 -c 'import sysconfig; [ print(f"""{k}={str(v).replace("$$","$$$$")}\n""") for k, v in sysconfig.get_config_vars().items() ]' >$@

sstpd/codec$(EXT_SUFFIX): sstpd/codecmodule.c
	$(CC) $(PY_CFLAGS) -fPIC -I$(INCLUDEPY) -c $^ -o $(<:.c=.o)
	$(LDSHARED) $(<:.c=.o) -L$(LIBDIR) -o $@
