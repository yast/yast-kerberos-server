# Sources for kerberos-server

module_DATA = \
  modules/KerberosServer.pm

client_DATA = \
  clients/kerberos-server.rb

yncludedir = @yncludedir@/kerberos-server
ynclude_DATA = \
  include/kerberos-server/wizards.rb \
  include/kerberos-server/advanced_items.rb \
  include/kerberos-server/complex.rb \
  include/kerberos-server/helps.rb

scrconf_DATA = \
  scrconf/kdc_conf.scr \
  scrconf/kadmin.scr \
  scrconf/krb5_conf.scr

agent_SCRIPTS = \
  servers_non_y2/ag_kadmin \
  servers_non_y2/ag_kerberos

desktop_DATA = \
  desktop/kerberos-server.desktop

EXTRA_DIST = $(module_DATA) $(client_DATA) $(ynclude_DATA) $(scrconf_DATA) $(agent_SCRIPTS) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common