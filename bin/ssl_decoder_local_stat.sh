#!/bin/bash

ARGC=$#
EXPORTER=/opt/tsg/framework/bin/fieldstat_exporter.py
TARGET=/opt/tsg/sapp/metrics/ssl_decoder_local_stat.json

case $1 in
    -h|--help)
        echo "$0"
        echo "Usage: [exporter] [target]"
        echo "  exporter: path of exporter, default is $EXPORTER"
        echo "  target: path of target file, default is $TARGET"
        exit 0
        ;;
esac

case $ARGC in
  	1)
		EXPORTER=$1
	  ;;
  	2)
		EXPORTER=$1
		TARGET=$2
	  ;;
esac
#new version
python3 $EXPORTER local -j $TARGET -e -t '
  {{"ssl decoder message"}}
  {{ print_tables("message_type", ["send", "#Speed<send>", "recv", "#Speed<recv>"], True )}} {{"\n"}} 

  {{"ssl decoder memory"}}
  {{ print_tables("memory", ["new", "#Speed<new>", "free", "#Speed<free>"], True )}} {{"\n"}} 

  {{"ssl decoder decode status"}}
  {{ print_tables("section", ["ok", "#Speed<ok>", "error", "#Speed<error>"], True )}} {{"\n"}}
'
