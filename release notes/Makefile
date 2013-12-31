Name	:= DigitalChinaSupplicant
Ver	:= 1.12

${Name}.${Ver}.zip: Installer.pkg
	mv Installer.pkg ${Name}.pkg
	zip $(Name) ${Name}.pkg
	mv ${Name}.zip $@
	ruby ../SignKeys/sign_update.rb $@ ../SignKeys/dsa_priv.pem

Installer.pkg:
	productbuild --distribution Distribution.xml --package-path .	\
		--resources ./Resources	\
		Installer.pkg

${Name}.pkg: ${Name}.app
	mkdir ${Name}
	mv ${Name}.app $(Name)/
	pkgbuild --root ${Name}		\
		--scripts ./Scripts	\
		--install-location "/Applications"	\
		${Name}.pkg

Distribution.xml: ${Name}.pkg
	productbuild --synthesize --package ${Name}.pkg Distribution.xml
	vi Distribution.xml

clean:
	rm -rf ${Name}
	rm -rf ${Name}.pkg
	rm -rf Installer.pkg
	rm -rf ${Name}.${Ver}.zip
