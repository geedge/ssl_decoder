#!/bin/sh
if [ $1 == 0 ]; then
	DST=${RPM_INSTALL_PREFIX}
	
	mkdir -p ${DST}/plug/protocol/
	touch ${DST}/plug/conflist.inf
	
	mkdir -p ${DST}/etc/
	touch ${DST}/etc/entrylist.conf

	sed -i '/ssl.inf/d' ${DST}/plug/conflist.inf
	sed -i '/ssl/d' ${DST}/etc/entrylist.conf
fi
