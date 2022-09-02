NAME=spf

PREFIX?=/usr/local
PERL!=which perl

help:
	@echo "The following targets are available:"
	@echo "clean    remove temporary files"
	@echo "install  install ${NAME} under ${PREFIX}"
	@echo "prep     update the perl path in the source script"
	@echo "readme   generate the README after a manual page update"

prep: src/${NAME}

src/${NAME}: src/${NAME}.pl
	sed -e "s|/usr/local/bin/perl|${PERL}|" $? >$@

install: prep
	mkdir -p ${PREFIX}/bin ${PREFIX}/share/man/man1
	install -c -m 555 src/${NAME} ${PREFIX}/bin/${NAME}
	install -c -m 444 doc/${NAME}.1 ${PREFIX}/share/man/man1/${NAME}.1

clean:
	rm -f src/${NAME}

man: doc/${NAME}.1.txt

doc/${NAME}.1.txt: doc/${NAME}.1
	mandoc -T ascii -c -O width=80 $? | col -b >$@

readme: man
	sed -n -e '/^NAME/!p;//q' README.md >.readme
	sed -n -e '/^NAME/,$$p' -e '/emailing/q' doc/${NAME}.1.txt >>.readme
	echo '```' >>.readme
	mv .readme README.md
