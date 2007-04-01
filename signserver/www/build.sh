#!/bin/sh

PAGES="admin.html building.html develop.html ha.html index.html misc.html quick-start.html ref.html signers.html test.html tokens.html"
LAYOUT="images style"
OUTDIR=../htdocs/


mkdir ${OUTDIR}

for fileOrDir in ${LAYOUT} ; do

	echo "removing ${OUTDIR}/${fileOrDir}"
	rm -rf ${OUTDIR}/${fileOrDir}
	echo "adding new ${OUTDIR}/${fileOrDir}"
	cp -r ${fileOrDir} ${OUTDIR}

done

for file in ${PAGES} ; do 

	echo "recreating ${OUTDIR}/${file}"
	# menu and the whole start of the page
	cat header.html >  ${OUTDIR}/${file}  

	# the content part
	cat ${file} >> ${OUTDIR}/${file}

	# right column and footer
	cat footer.html >> ${OUTDIR}/${file}

done


