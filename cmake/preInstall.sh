#!/bin/sh
INSTALL_PREFIX=${RPM_INSTALL_PREFIX}/sapp/

mkdir ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin/ -p
touch ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin/spec.toml

if [[ -z `grep -rn 'ssl_decoder' ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin/spec.toml` ]];then
	echo -e "" >> ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin/spec.toml
	echo -e "[[plugin]]" >> ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin/spec.toml
	echo -e "path=\"./stellar_plugin/ssl_decoder.so\"" >> ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin//spec.toml
	echo -e "init=\"ssl_decoder_init\"" >> ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin/spec.toml
	echo -e "exit=\"ssl_decoder_exit\"" >> ${RPM_INSTALL_PREFIX}/sapp/stellar_plugin/spec.toml
fi

