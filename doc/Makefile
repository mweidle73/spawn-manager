DESTDIR ?= html
PREPARE := $(shell mkdir -p $(DESTDIR))

ASCIIDOC_OPTS = \
	-a icons=font \
	-a iconfont-remote! \
	-a stylesdir=doc/css \
	-a stylesheet=styles.css \
	-a sectanchors \
	-o -

all: $(DESTDIR)/index.html

$(DESTDIR)/index.html: ../README css/styles.css
	TZ=UTC asciidoctor $(ASCIIDOC_OPTS) $< > $@

clean:
	@rm -rf $(DESTDIR)
