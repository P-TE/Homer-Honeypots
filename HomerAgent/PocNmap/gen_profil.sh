#!/bin/bash
if [ $# -ne 2 ]; then
	echo "$# args"
	echo 'usage: ./gen_profil.sh <in.profil> <out.conf>'
else
	cat $1 | sed 's/^\(.*\)(\(\)/\n[\1]\n\2/g' | sed 's/%/\n/g' | sed 's/)//g' > $2
	echo 'Done'
fi
