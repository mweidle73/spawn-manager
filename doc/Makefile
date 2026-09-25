DESTDIR ?= html
PANDOC  ?= pandoc

PANDOC_OPTS = \
	--from=gfm \
	--to=html5 \
	--standalone \
	--toc \
	--css=styles.css

HTML_DOCUMENTS = \
	$(DESTDIR)/index.html \
	$(DESTDIR)/CHANGELOG.html \
	$(DESTDIR)/protocol-v1.html \
	$(DESTDIR)/lifecycle-v1.html \
	$(DESTDIR)/styles.css

all: $(HTML_DOCUMENTS)

$(DESTDIR):
	mkdir -p $@

$(DESTDIR)/index.html: ../README.md | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Ada Spawn Manager" \
		-o $@.tmp $<
	sed \
		-e 's|href="CHANGELOG.md"|href="CHANGELOG.html"|g' \
		-e 's|href="doc/protocol-v1.md"|href="protocol-v1.html"|g' \
		-e 's|href="doc/lifecycle-v1.md"|href="lifecycle-v1.html"|g' \
		$@.tmp > $@
	rm -f $@.tmp

$(DESTDIR)/CHANGELOG.html: ../CHANGELOG.md | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Spawn Manager changelog" \
		-o $@ $<

$(DESTDIR)/protocol-v1.html: protocol-v1.md | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Protocol version 1" \
		-o $@ $<

$(DESTDIR)/lifecycle-v1.html: lifecycle-v1.md | $(DESTDIR)
	$(PANDOC) $(PANDOC_OPTS) --metadata pagetitle="Lifecycle version 1" \
		-o $@.tmp $<
	sed \
		-e 's|href="protocol-v1.md|href="protocol-v1.html|g' \
		$@.tmp > $@
	rm -f $@.tmp

$(DESTDIR)/styles.css: css/styles.css | $(DESTDIR)
	cp $< $@

clean:
	@rm -rf $(DESTDIR)

.PHONY: all clean
