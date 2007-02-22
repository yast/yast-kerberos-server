# Makefile.am for kerberos-server/src

yncludedir = @yncludedir@/kerberos-server

client_DATA =			\
	kerberos-server.ycp		

ynclude_DATA =			\
	helps.ycp		\
	wizards.ycp		\
	complex.ycp		\
	advanced_items.ycp

desktop_DATA =			\
	kerberos-server.desktop

module_DATA =			\
	KerberosServer.pm

# create a symlink for local build, #145327
kerberos-server:
	ln -sf . $@
ycpchook = kerberos-server

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common
