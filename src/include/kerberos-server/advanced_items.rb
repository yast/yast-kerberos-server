# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2006 Novell, Inc. All Rights Reserved.
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail, you may find
# current contact information at www.novell.com.
# ------------------------------------------------------------------------------

# File:	clients/kerberos-server.ycp
# Package:	Configuration of kerberos-server
# Summary:	Main file
# Authors:	Michael Calmer <mc@novell.com>
#
# $Id: kerberos-server.ycp 27914 2006-02-13 14:32:08Z locilka $
#
# Main file for kerberos-server configuration. Uses all other files.
module Yast
  module KerberosServerAdvancedItemsInclude
    def initialize_kerberos_server_advanced_items(include_target)
      textdomain "kerberos-server"

      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "KerberosServer"

      # #################################################################################
      # #################################################################################
      # #################################################################################



      # #################################################################################

      @itemMap = {
        :advanced                     => {
          "name"   => _("Advanced Settings"),
          "widget" => RichText(Id(:id_advanced), "")
        },
        :database_name                => {
          "name"        => _("Database Path"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_database_name),
                Opt(:hstretch),
                _("&Database Path"),
                KerberosServer.getDBvalue("database_name")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_database_name", ""))
            )
          ),
          "getCallback" => lambda { get_adv_database_name },
          "setCallback" => lambda { set_adv_database_name }
        },
        :acl_file                     => {
          "name"        => _("ACL File"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_acl_file),
                Opt(:hstretch),
                _("ACL &File"),
                KerberosServer.getDBvalue("acl_file")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_acl_file", ""))
            )
          ),
          "getCallback" => lambda { get_adv_acl_file },
          "setCallback" => lambda { set_adv_acl_file }
        },
        :admin_keytab                 => {
          "name"        => _("Administrator Keytab"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_admin_keytab),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("admin_keytab")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_admin_keytab", ""))
            )
          ),
          "getCallback" => lambda { get_adv_admin_keytab },
          "setCallback" => lambda { set_adv_admin_keytab }
        },
        :default_principal_expiration => {
          "name"        => _("Default Principal Expiration"),
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_default_principal_expiration_available),
                  Opt(:notify),
                  # checkbox text
                  _("&Available"),
                  true
                )
              ),
              HBox(
                UI.HasSpecialWidget(:DateField) == true ?
                  DateField(
                    Id(:id_default_principal_expiration_date),
                    _("&Date")
                  ) :
                  InputField(
                    Id(:id_default_principal_expiration_date),
                    Opt(:hstretch),
                    _("&Date"),
                    ""
                  ),
                UI.HasSpecialWidget(:TimeField) == true ?
                  TimeField(
                    Id(:id_default_principal_expiration_time),
                    _("&Time")
                  ) :
                  InputField(
                    Id(:id_default_principal_expiration_time),
                    Opt(:hstretch),
                    _("&Time"),
                    ""
                  )
              ),
              #
              # `InputField(`opt(`hstretch),`id(`id_default_principal_expiration),"",
              # KerberosServer::getDBvalue("default_principal_expiration")),
              VSpacing(1.5),
              RichText(
                Ops.get_string(@HELPS, "adv_default_principal_expiration", "")
              )
            )
          ),
          "default"     => lambda { get_adv_default_principal_expiration },
          "getCallback" => lambda { get_adv_default_principal_expiration },
          "setCallback" => lambda { set_adv_default_principal_expiration }
        },
        :default_principal_flags      => {
          "name"        => _("Default Principal Flags"),
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:kdc_flags_allow_postdated),
                  # checkbox text in MultiSelectionBox
                  _("Allow p&ostdated"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_allow_forwardable),
                  # checkbox text in MultiSelectionBox
                  _("Allow &forwardable"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_allow_renewable),
                  # checkbox text in MultiSelectionBox
                  _("Allow rene&wable"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_allow_proxiable),
                  # checkbox text in MultiSelectionBox
                  _("Allow &proxiable"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_allow_dup_skey),
                  # checkbox text in MultiSelectionBox
                  _("Enable &user-to-user authentication"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_requires_preauth),
                  # checkbox text in MultiSelectionBox
                  _("Requires pr&eauth"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_requires_hwauth),
                  # checkbox text in MultiSelectionBox
                  _("Requires &hwauth"),
                  false
                )
              ),
              # checkbox text in MultiSelectionBox
              Left(
                CheckBox(Id(:kdc_flags_allow_svr), _("Allow &service"), false)
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_allow_tgs_req),
                  # checkbox text in MultiSelectionBox
                  _("Allow tgs re&quest"),
                  false
                )
              ),
              # checkbox text in MultiSelectionBox
              Left(
                CheckBox(Id(:kdc_flags_allow_tix), _("Allow &tickets"), false)
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_needchange),
                  # checkbox text in MultiSelectionBox
                  _("Need &change"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdc_flags_password_changing_service),
                  # checkbox text in MultiSelectionBox
                  _("P&assword changing service"),
                  false
                )
              ),
              VSpacing(1.5),
              RichText(
                Ops.get_string(@HELPS, "adv_default_principal_flags", "")
              )
            )
          ),
          "default"     => lambda { get_adv_default_principal_flags },
          "getCallback" => lambda { get_adv_default_principal_flags },
          "setCallback" => lambda { set_adv_default_principal_flags }
        },
        :dict_file                    => {
          "name"        => _("Dictionary File"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_dict_file),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("dict_file")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_dict_file", ""))
            )
          ),
          "getCallback" => lambda { get_adv_dict_file },
          "setCallback" => lambda { set_adv_dict_file }
        },
        :kadmind_port                 => {
          "name"        => _("Kadmin Daemon Port"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_kadmind_port),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("kadmind_port")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kadmind_port", ""))
            )
          ),
          "getCallback" => lambda { get_adv_kadmind_port },
          "setCallback" => lambda { set_adv_kadmind_port }
        },
        :kpasswd_port                 => {
          "name"        => _("Kpasswd Daemon Port"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_kpasswd_port),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("kpasswd_port")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kpasswd_port", ""))
            )
          ),
          "getCallback" => lambda { get_adv_kpasswd_port },
          "setCallback" => lambda { set_adv_kpasswd_port }
        },
        :key_stash_file               => {
          "name"        => _("Key Stash File"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_key_stash_file),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("key_stash_file")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_key_stash_file", ""))
            )
          ),
          "getCallback" => lambda { get_adv_key_stash_file },
          "setCallback" => lambda { set_adv_key_stash_file }
        },
        :kdc_ports                    => {
          "name"        => _("KDC Port"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_kdc_ports),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("kdc_ports")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kdc_ports", ""))
            )
          ),
          "getCallback" => lambda { get_adv_kdc_ports },
          "setCallback" => lambda { set_adv_kdc_ports }
        },
        :master_key_name              => {
          "name"        => _("Master Key Name"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_master_key_name),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("master_key_name")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_master_key_name", ""))
            )
          ),
          "getCallback" => lambda { get_adv_master_key_name },
          "setCallback" => lambda { set_adv_master_key_name }
        },
        :master_key_type              => {
          "name"        => _("Master Key Type"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_master_key_type),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("master_key_type")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_master_key_type", ""))
            )
          ),
          "getCallback" => lambda { get_adv_master_key_type },
          "setCallback" => lambda { set_adv_master_key_type }
        },
        :max_life                     => {
          "name"        => _("Maximum Ticket Life Time"),
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_max_life_available),
                  Opt(:notify),
                  # checkbox text
                  _("&Available"),
                  true
                )
              ),
              HBox(
                IntField(Id(:id_max_life_days), _("&Days"), 0, 365, 0),
                UI.HasSpecialWidget(:Time) == true ?
                  term(:Time, Id(:id_max_life_time), _("&Time")) :
                  InputField(
                    Id(:id_max_life_time),
                    Opt(:hstretch),
                    _("&Time"),
                    ""
                  )
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_max_life", ""))
            )
          ),
          "default"     => lambda { get_adv_max_life },
          "getCallback" => lambda { get_adv_max_life },
          "setCallback" => lambda { set_adv_max_life }
        },
        :max_renewable_life           => {
          "name"        => _("Maximum Ticket Renew Time"),
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_max_renewable_life_available),
                  Opt(:notify),
                  # checkbox text
                  _("&Available"),
                  true
                )
              ),
              HBox(
                IntField(Id(:id_max_renewable_life_days), _("&Days"), 0, 365, 0),
                UI.HasSpecialWidget(:Time) == true ?
                  term(:Time, Id(:id_max_renewable_life_time), _("&Time")) :
                  InputField(
                    Id(:id_max_renewable_life_time),
                    Opt(:hstretch),
                    _("&Time"),
                    ""
                  )
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_max_renew_life", ""))
            )
          ),
          "default"     => lambda { get_adv_max_renewable_life },
          "getCallback" => lambda { get_adv_max_renewable_life },
          "setCallback" => lambda { set_adv_max_renewable_life }
        },
        :supported_enctypes           => {
          "name"        => _("Default Encryption Types"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_supported_enctypes),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("supported_enctypes")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_supported_enctypes", ""))
            )
          ),
          "getCallback" => lambda { get_adv_supported_enctypes },
          "setCallback" => lambda { set_adv_supported_enctypes }
        },
        :kdc_supported_enctypes       => {
          "name"        => _("KDC Supported Encryption Types"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_kdc_supported_enctypes),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("kdc_supported_enctypes")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kdc_supported_enctypes", ""))
            )
          ),
          "getCallback" => lambda { get_adv_kdc_supported_enctypes },
          "setCallback" => lambda { set_adv_kdc_supported_enctypes }
        },
        :reject_bad_transit           => {
          "name"        => _("Reject Bad Transit"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_reject_bad_transit),
                Opt(:hstretch),
                "",
                KerberosServer.getDBvalue("reject_bad_transit")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_reject_bad_transit", ""))
            )
          ),
          "getCallback" => lambda { get_adv_reject_bad_transit },
          "setCallback" => lambda { set_adv_reject_bad_transit }
        },
        :ldap_conns_per_server        => {
          "name"        => _("Number of LDAP connections"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_ldap_conns_per_server),
                Opt(:hstretch),
                "",
                KerberosServer.getLdapDBvalue("ldap_conns_per_server")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_ldap_conns_per_server", ""))
            )
          ),
          "getCallback" => lambda { get_adv_ldap_conns_per_server },
          "setCallback" => lambda { set_adv_ldap_conns_per_server }
        },
        :ldap_service_password_file   => {
          "name"        => _("File for the LDAP password"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_ldap_service_password_file),
                Opt(:hstretch),
                "",
                KerberosServer.getLdapDBvalue("ldap_service_password_file")
              ),
              VSpacing(1.5),
              RichText(
                Ops.get_string(@HELPS, "adv_ldap_service_password_file", "")
              )
            )
          ),
          "getCallback" => lambda { get_adv_ldap_service_password_file },
          "setCallback" => lambda { set_adv_ldap_service_password_file }
        },
        :kdb_subtrees                 => {
          "name"        => _("Search Subtrees"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_kdb_subtrees),
                Opt(:hstretch),
                "",
                KerberosServer.getKdbvalue("kdb_subtrees")
              ),
              VSpacing(1.5),
              Left(
                Frame(
                  _("Search Scope"),
                  RadioButtonGroup(
                    Id(:rb),
                    VBox(
                      Left(
                        RadioButton(
                          Id(:sub),
                          _("&subtree search"),
                          KerberosServer.getKdbvalue("kdb_sscope") == "sub" ? true : false
                        )
                      ),
                      Left(
                        RadioButton(
                          Id(:one),
                          _("&one level"),
                          KerberosServer.getKdbvalue("kdb_sscope") == "sub" ? false : true
                        )
                      )
                    )
                  )
                )
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kdb_subtrees", ""))
            )
          ),
          "getCallback" => lambda { get_adv_kdb_subtrees },
          "setCallback" => lambda { set_adv_kdb_subtrees }
        },
        :kdb_containerref             => {
          "name"        => _("Principal Container"),
          "widget"      => Frame(
            "",
            VBox(
              InputField(
                Id(:id_kdb_containerref),
                Opt(:hstretch),
                "",
                KerberosServer.getKdbvalue("kdb_containerref")
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kdb_containerref", ""))
            )
          ),
          "getCallback" => lambda { get_adv_kdb_containerref },
          "setCallback" => lambda { set_adv_kdb_containerref }
        },
        :kdb_maxtktlife               => {
          "name"        => _("Maximum Ticket Life Time"),
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_kdb_maxtktlife_available),
                  Opt(:notify),
                  # checkbox text
                  _("&Available"),
                  true
                )
              ),
              HBox(
                IntField(Id(:id_kdb_maxtktlife_days), _("&Days"), 0, 365, 0),
                UI.HasSpecialWidget(:Time) == true ?
                  term(:Time, Id(:id_kdb_maxtktlife_time), _("&Time")) :
                  InputField(
                    Id(:id_kdb_maxtktlife_time),
                    Opt(:hstretch),
                    _("&Time"),
                    ""
                  )
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kdb_maxtktlife", ""))
            )
          ),
          "default"     => lambda { get_adv_kdb_maxtktlife },
          "getCallback" => lambda { get_adv_kdb_maxtktlife },
          "setCallback" => lambda { set_adv_kdb_maxtktlife }
        },
        :kdb_maxrenewlife             => {
          "name"        => _("Maximum Ticket Renew Time"),
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:id_kdb_maxrenewlife_available),
                  Opt(:notify),
                  # checkbox text
                  _("&Available"),
                  true
                )
              ),
              HBox(
                IntField(Id(:id_kdb_maxrenewlife_days), _("&Days"), 0, 365, 0),
                UI.HasSpecialWidget(:Time) == true ?
                  term(:Time, Id(:id_kdb_maxrenewlife_time), _("&Time")) :
                  InputField(
                    Id(:id_kdb_maxrenewlife_time),
                    Opt(:hstretch),
                    _("&Time"),
                    ""
                  )
              ),
              VSpacing(1.5),
              RichText(Ops.get_string(@HELPS, "adv_kdb_maxrenewlife", ""))
            )
          ),
          "default"     => lambda { get_adv_kdb_maxrenewlife },
          "getCallback" => lambda { get_adv_kdb_maxrenewlife },
          "setCallback" => lambda { set_adv_kdb_maxrenewlife }
        },
        :kdb_flags                    => {
          "name"        => _("Default Principal Flags"),
          "widget"      => Frame(
            "",
            VBox(
              Left(
                CheckBox(
                  Id(:kdb_flags_allow_postdated),
                  # checkbox text in MultiSelectionBox
                  _("Allow p&ostdated"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_allow_forwardable),
                  # checkbox text in MultiSelectionBox
                  _("Allow &forwardable"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_allow_renewable),
                  # checkbox text in MultiSelectionBox
                  _("Allow rene&wable"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_allow_proxiable),
                  # checkbox text in MultiSelectionBox
                  _("Allow &proxiable"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_allow_dup_skey),
                  # checkbox text in MultiSelectionBox
                  _("Enable &user-to-user authentication"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_requires_preauth),
                  # checkbox text in MultiSelectionBox
                  _("Requires pr&eauth"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_requires_hwauth),
                  # checkbox text in MultiSelectionBox
                  _("Requires &hwauth"),
                  false
                )
              ),
              # checkbox text in MultiSelectionBox
              Left(
                CheckBox(Id(:kdb_flags_allow_svr), _("Allow &service"), false)
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_allow_tgs_req),
                  # checkbox text in MultiSelectionBox
                  _("Allow tgs re&quest"),
                  false
                )
              ),
              # checkbox text in MultiSelectionBox
              Left(
                CheckBox(Id(:kdb_flags_allow_tix), _("Allow &tickets"), false)
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_needchange),
                  # checkbox text in MultiSelectionBox
                  _("Need &change"),
                  false
                )
              ),
              Left(
                CheckBox(
                  Id(:kdb_flags_password_changing_service),
                  # checkbox text in MultiSelectionBox
                  _("P&assword changing service"),
                  false
                )
              ),
              VSpacing(1.5),
              RichText(
                Ops.get_string(@HELPS, "adv_default_principal_flags", "")
              )
            )
          ),
          "default"     => lambda { get_adv_kdb_flags },
          "getCallback" => lambda { get_adv_kdb_flags },
          "setCallback" => lambda { set_adv_kdb_flags }
        }
      }
    end

    # #################################################################################
    # #################################################################################
    # #################################################################################

    def get_adv_acl_file
      Builtins.y2debug("calling get_adv_acl_file")

      UI.ChangeWidget(
        Id(:id_acl_file),
        :Value,
        KerberosServer.getDBvalue("acl_file")
      )

      nil
    end

    def set_adv_acl_file
      Builtins.y2debug("calling set_adv_acl_file")

      KerberosServer.setDBvalue(
        "acl_file",
        Convert.to_string(UI.QueryWidget(Id(:id_acl_file), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_admin_keytab
      Builtins.y2debug("calling get_adv_admin_keytab")

      UI.ChangeWidget(
        Id(:id_admin_keytab),
        :Value,
        KerberosServer.getDBvalue("admin_keytab")
      )

      nil
    end

    def set_adv_admin_keytab
      Builtins.y2debug("calling set_adv_admin_keytab")

      KerberosServer.setDBvalue(
        "admin_keytab",
        Convert.to_string(UI.QueryWidget(Id(:id_admin_keytab), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_default_principal_expiration
      Builtins.y2milestone("calling get_adv_default_principal_expiration")

      datetime = KerberosServer.getDBvalue("default_principal_expiration")

      Builtins.y2milestone("get: datetime = %1", datetime)

      UI.ChangeWidget(
        Id(:id_default_principal_expiration_available),
        :Value,
        datetime == "" ? false : true
      )

      dt = KerberosServer.decodeDateTime(datetime)

      UI.ChangeWidget(
        Id(:id_default_principal_expiration_date),
        :Value,
        Ops.get(dt, 0, "2007-01-01")
      )
      UI.ChangeWidget(
        Id(:id_default_principal_expiration_time),
        :Value,
        Ops.get(dt, 1, "00:00:00")
      )

      UI.ChangeWidget(
        Id(:id_default_principal_expiration_date),
        :Enabled,
        KerberosServer.getDBvalue("default_principal_expiration") == "" ? false : true
      )
      UI.ChangeWidget(
        Id(:id_default_principal_expiration_time),
        :Enabled,
        KerberosServer.getDBvalue("default_principal_expiration") == "" ? false : true
      )

      nil
    end

    def set_adv_default_principal_expiration
      Builtins.y2milestone("calling set_adv_default_principal_expiration")

      if Convert.to_boolean(
          UI.QueryWidget(Id(:id_default_principal_expiration_available), :Value)
        ) == false
        Builtins.y2milestone("checkbox is off")
        KerberosServer.setDBvalue("default_principal_expiration", "")
      else
        Builtins.y2milestone("checkbox is on")
        _Date = Convert.to_string(
          UI.QueryWidget(Id(:id_default_principal_expiration_date), :Value)
        )
        _Time = Convert.to_string(
          UI.QueryWidget(Id(:id_default_principal_expiration_time), :Value)
        )

        datetime = KerberosServer.encodeDateTime(_Date, _Time)

        Builtins.y2milestone("set: datetime = %1", datetime)

        KerberosServer.setDBvalue("default_principal_expiration", datetime)
      end

      nil
    end

    # #################################################################################

    def get_adv_default_principal_flags
      Builtins.y2debug("calling get_adv_default_principal_flags")

      flags = KerberosServer.getDBvalue("default_principal_flags")

      UI.ChangeWidget(
        Id(:kdc_flags_allow_postdated),
        :Value,
        Builtins.issubstring(flags, "-postdateable") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_allow_forwardable),
        :Value,
        Builtins.issubstring(flags, "-forwardable") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_allow_renewable),
        :Value,
        Builtins.issubstring(flags, "-renewable") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_allow_proxiable),
        :Value,
        Builtins.issubstring(flags, "-proxiable") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_allow_dup_skey),
        :Value,
        Builtins.issubstring(flags, "-dup-skey") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_requires_preauth),
        :Value,
        Builtins.issubstring(flags, "+preauth") ? true : false
      )
      UI.ChangeWidget(
        Id(:kdc_flags_requires_hwauth),
        :Value,
        Builtins.issubstring(flags, "+hwauth") ? true : false
      )
      UI.ChangeWidget(
        Id(:kdc_flags_allow_svr),
        :Value,
        Builtins.issubstring(flags, "-service") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_allow_tgs_req),
        :Value,
        Builtins.issubstring(flags, "-tgt-based") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_allow_tix),
        :Value,
        Builtins.issubstring(flags, "-allow-tickets") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdc_flags_needchange),
        :Value,
        Builtins.issubstring(flags, "+pwchange") ? true : false
      )
      UI.ChangeWidget(
        Id(:kdc_flags_password_changing_service),
        :Value,
        Builtins.issubstring(flags, "+pwservice") ? true : false
      )

      nil
    end

    def set_adv_default_principal_flags
      Builtins.y2debug("calling set_adv_default_principal_flags")

      flags = ""

      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_allow_postdated), :Value)
        )
        flags = Ops.add(flags, "+postdateable ")
      else
        flags = Ops.add(flags, "-postdateable ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_allow_forwardable), :Value)
        )
        flags = Ops.add(flags, "+forwardable ")
      else
        flags = Ops.add(flags, "-forwardable ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_allow_renewable), :Value)
        )
        flags = Ops.add(flags, "+renewable ")
      else
        flags = Ops.add(flags, "-renewable ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_allow_proxiable), :Value)
        )
        flags = Ops.add(flags, "+proxiable ")
      else
        flags = Ops.add(flags, "-proxiable ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_allow_dup_skey), :Value)
        )
        flags = Ops.add(flags, "+dup-skey ")
      else
        flags = Ops.add(flags, "-dup-skey ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_requires_preauth), :Value)
        )
        flags = Ops.add(flags, "+preauth ")
      else
        flags = Ops.add(flags, "-preauth ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_requires_hwauth), :Value)
        )
        flags = Ops.add(flags, "+hwauth ")
      else
        flags = Ops.add(flags, "-hwauth ")
      end
      if Convert.to_boolean(UI.QueryWidget(Id(:kdc_flags_allow_svr), :Value))
        flags = Ops.add(flags, "+service ")
      else
        flags = Ops.add(flags, "-service ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_allow_tgs_req), :Value)
        )
        flags = Ops.add(flags, "+tgt-based ")
      else
        flags = Ops.add(flags, "-tgt-based ")
      end
      if Convert.to_boolean(UI.QueryWidget(Id(:kdc_flags_allow_tix), :Value))
        flags = Ops.add(flags, "+allow-tickets ")
      else
        flags = Ops.add(flags, "-allow-tickets ")
      end
      if Convert.to_boolean(UI.QueryWidget(Id(:kdc_flags_needchange), :Value))
        flags = Ops.add(flags, "+pwchange ")
      else
        flags = Ops.add(flags, "-pwchange ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdc_flags_password_changing_service), :Value)
        )
        flags = Ops.add(flags, "+pwservice ")
      else
        flags = Ops.add(flags, "-pwservice ")
      end

      KerberosServer.setDBvalue("default_principal_flags", flags)

      nil
    end

    # #################################################################################

    def get_adv_dict_file
      Builtins.y2debug("calling get_adv_dict_file")

      UI.ChangeWidget(
        Id(:id_dict_file),
        :Value,
        KerberosServer.getDBvalue("dict_file")
      )

      nil
    end

    def set_adv_dict_file
      Builtins.y2debug("calling set_adv_dict_file")

      KerberosServer.setDBvalue(
        "dict_file",
        Convert.to_string(UI.QueryWidget(Id(:id_dict_file), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_kadmind_port
      Builtins.y2debug("calling get_adv_kadmind_port")

      UI.ChangeWidget(
        Id(:id_kadmind_port),
        :Value,
        KerberosServer.getDBvalue("kadmind_port")
      )

      nil
    end

    def set_adv_kadmind_port
      Builtins.y2debug("calling set_adv_kadmind_port")

      KerberosServer.setDBvalue(
        "kadmind_port",
        Convert.to_string(UI.QueryWidget(Id(:id_kadmind_port), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_kpasswd_port
      Builtins.y2debug("calling get_adv_kpasswd_port")

      UI.ChangeWidget(
        Id(:id_kpasswd_port),
        :Value,
        KerberosServer.getDBvalue("kpasswd_port")
      )

      nil
    end

    def set_adv_kpasswd_port
      Builtins.y2debug("calling set_adv_kpasswd_port")

      KerberosServer.setDBvalue(
        "kpasswd_port",
        Convert.to_string(UI.QueryWidget(Id(:id_kpasswd_port), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_key_stash_file
      Builtins.y2debug("calling get_adv_key_stash_file")

      UI.ChangeWidget(
        Id(:id_key_stash_file),
        :Value,
        KerberosServer.getDBvalue("key_stash_file")
      )

      nil
    end

    def set_adv_key_stash_file
      Builtins.y2debug("calling set_adv_key_stash_file")

      KerberosServer.setDBvalue(
        "key_stash_file",
        Convert.to_string(UI.QueryWidget(Id(:id_key_stash_file), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_kdc_ports
      Builtins.y2debug("calling get_adv_kdc_ports")

      UI.ChangeWidget(
        Id(:id_kdc_ports),
        :Value,
        KerberosServer.getDBvalue("kdc_ports")
      )

      nil
    end

    def set_adv_kdc_ports
      Builtins.y2debug("calling set_adv_kdc_ports")

      KerberosServer.setDBvalue(
        "kdc_ports",
        Convert.to_string(UI.QueryWidget(Id(:id_kdc_ports), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_master_key_name
      Builtins.y2debug("calling get_adv_master_key_name")

      UI.ChangeWidget(
        Id(:id_master_key_name),
        :Value,
        KerberosServer.getDBvalue("master_key_name")
      )

      nil
    end

    def set_adv_master_key_name
      Builtins.y2debug("calling set_adv_master_key_name")

      KerberosServer.setDBvalue(
        "master_key_name",
        Convert.to_string(UI.QueryWidget(Id(:id_master_key_name), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_master_key_type
      Builtins.y2debug("calling get_adv_master_key_type")

      UI.ChangeWidget(
        Id(:id_master_key_type),
        :Value,
        KerberosServer.getDBvalue("master_key_type")
      )

      nil
    end

    def set_adv_master_key_type
      Builtins.y2debug("calling set_adv_master_key_type")

      KerberosServer.setDBvalue(
        "master_key_type",
        Convert.to_string(UI.QueryWidget(Id(:id_master_key_type), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_max_life
      Builtins.y2milestone("calling get_adv_max_life")

      t = KerberosServer.splitTime(KerberosServer.getDBvalue("max_life"))

      UI.ChangeWidget(
        Id(:id_max_life_available),
        :Value,
        KerberosServer.getDBvalue("max_life") == "" ? false : true
      )


      UI.ChangeWidget(
        Id(:id_max_life_days),
        :Value,
        Builtins.tointeger(Ops.get_string(t, 0, "0"))
      )
      UI.ChangeWidget(
        Id(:id_max_life_time),
        :Value,
        Ops.get_string(t, 1, "01:00:00")
      )

      UI.ChangeWidget(
        Id(:id_max_life_days),
        :Enabled,
        KerberosServer.getDBvalue("max_life") == "" ? false : true
      )
      UI.ChangeWidget(
        Id(:id_max_life_time),
        :Enabled,
        KerberosServer.getDBvalue("max_life") == "" ? false : true
      )

      nil
    end

    def set_adv_max_life
      Builtins.y2milestone("calling set_adv_max_life")

      if Convert.to_boolean(UI.QueryWidget(Id(:id_max_life_available), :Value)) == false
        KerberosServer.setDBvalue("max_life", "")
      else
        s = Builtins.tostring(
          Convert.to_integer(UI.QueryWidget(Id(:id_max_life_days), :Value))
        )
        s = Ops.add(s, " ")
        s = Ops.add(
          s,
          Convert.to_string(UI.QueryWidget(Id(:id_max_life_time), :Value))
        )

        KerberosServer.setDBvalue("max_life", s)
      end

      nil
    end

    # #################################################################################

    def get_adv_max_renewable_life
      Builtins.y2debug("calling get_adv_max_renewable_life")

      t = KerberosServer.splitTime(
        KerberosServer.getDBvalue("max_renewable_life")
      )

      UI.ChangeWidget(
        Id(:id_max_renewable_life_available),
        :Value,
        KerberosServer.getDBvalue("max_renewable_life") == "" ? false : true
      )


      UI.ChangeWidget(
        Id(:id_max_renewable_life_days),
        :Value,
        Builtins.tointeger(Ops.get_string(t, 0, "0"))
      )
      UI.ChangeWidget(
        Id(:id_max_renewable_life_time),
        :Value,
        Ops.get_string(t, 1, "01:00:00")
      )

      UI.ChangeWidget(
        Id(:id_max_renewable_life_days),
        :Enabled,
        KerberosServer.getDBvalue("max_renewable_life") == "" ? false : true
      )
      UI.ChangeWidget(
        Id(:id_max_renewable_life_time),
        :Enabled,
        KerberosServer.getDBvalue("max_renewable_life") == "" ? false : true
      )

      nil
    end

    def set_adv_max_renewable_life
      Builtins.y2debug("calling set_adv_max_renewable_life")

      if Convert.to_boolean(
          UI.QueryWidget(Id(:id_max_renewable_life_available), :Value)
        ) == false
        KerberosServer.setDBvalue("max_renewable_life", "")
      else
        s = Builtins.tostring(
          Convert.to_integer(
            UI.QueryWidget(Id(:id_max_renewable_life_days), :Value)
          )
        )
        s = Ops.add(s, " ")
        s = Ops.add(
          s,
          Convert.to_string(
            UI.QueryWidget(Id(:id_max_renewable_life_time), :Value)
          )
        )

        KerberosServer.setDBvalue("max_renewable_life", s)
      end

      nil
    end

    # #################################################################################

    def get_adv_supported_enctypes
      Builtins.y2debug("calling get_adv_supported_enctypes")

      UI.ChangeWidget(
        Id(:id_supported_enctypes),
        :Value,
        KerberosServer.getDBvalue("supported_enctypes")
      )

      nil
    end

    def set_adv_supported_enctypes
      Builtins.y2debug("calling set_adv_supported_enctypes")

      KerberosServer.setDBvalue(
        "supported_enctypes",
        Convert.to_string(UI.QueryWidget(Id(:id_supported_enctypes), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_kdc_supported_enctypes
      Builtins.y2debug("calling get_adv_kdc_supported_enctypes")

      UI.ChangeWidget(
        Id(:id_kdc_supported_enctypes),
        :Value,
        KerberosServer.getDBvalue("kdc_supported_enctypes")
      )

      nil
    end

    def set_adv_kdc_supported_enctypes
      Builtins.y2debug("calling set_adv_kdc_supported_enctypes")

      KerberosServer.setDBvalue(
        "kdc_supported_enctypes",
        Convert.to_string(
          UI.QueryWidget(Id(:id_kdc_supported_enctypes), :Value)
        )
      )

      nil
    end

    # #################################################################################

    def get_adv_reject_bad_transit
      Builtins.y2debug("calling get_adv_reject_bad_transit")

      UI.ChangeWidget(
        Id(:id_reject_bad_transit),
        :Value,
        KerberosServer.getDBvalue("reject_bad_transit")
      )

      nil
    end

    def set_adv_reject_bad_transit
      Builtins.y2debug("calling set_adv_reject_bad_transit")

      KerberosServer.setDBvalue(
        "reject_bad_transit",
        Convert.to_string(UI.QueryWidget(Id(:id_reject_bad_transit), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_database_name
      Builtins.y2debug("calling get_adv_database_name")

      UI.ChangeWidget(
        Id(:id_database_name),
        :Value,
        KerberosServer.getDBvalue("database_name")
      )

      nil
    end

    def set_adv_database_name
      Builtins.y2debug("calling set_adv_database_name")

      KerberosServer.setDBvalue(
        "database_name",
        Convert.to_string(UI.QueryWidget(Id(:id_database_name), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_ldap_conns_per_server
      Builtins.y2debug("calling get_adv_ldap_conns_per_server")

      UI.ChangeWidget(
        Id(:id_ldap_conns_per_server),
        :Value,
        KerberosServer.getLdapDBvalue("ldap_conns_per_server")
      )

      nil
    end

    def set_adv_ldap_conns_per_server
      Builtins.y2debug("calling set_adv_ldap_conns_per_server")

      KerberosServer.setLdapDBvalue(
        "ldap_conns_per_server",
        Convert.to_string(UI.QueryWidget(Id(:id_ldap_conns_per_server), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_ldap_service_password_file
      Builtins.y2debug("calling get_adv_ldap_service_password_file")

      UI.ChangeWidget(
        Id(:id_ldap_service_password_file),
        :Value,
        KerberosServer.getLdapDBvalue("ldap_service_password_file")
      )

      nil
    end

    def set_adv_ldap_service_password_file
      Builtins.y2debug("calling set_adv_ldap_service_password_file")

      KerberosServer.setLdapDBvalue(
        "ldap_service_password_file",
        Convert.to_string(
          UI.QueryWidget(Id(:id_ldap_service_password_file), :Value)
        )
      )

      nil
    end

    # #################################################################################

    def get_adv_kdb_subtrees
      Builtins.y2debug("calling get_adv_kdb_subtrees")

      UI.ChangeWidget(
        Id(:id_kdb_subtrees),
        :Value,
        KerberosServer.getKdbvalue("kdb_subtrees")
      )

      UI.ChangeWidget(
        Id(:sub),
        :Value,
        KerberosServer.getKdbvalue("kdb_sscope") == "sub" ? true : false
      )
      UI.ChangeWidget(
        Id(:one),
        :Value,
        KerberosServer.getKdbvalue("kdb_sscope") == "sub" ? false : true
      )

      nil
    end

    def set_adv_kdb_subtrees
      Builtins.y2debug("calling set_adv_kdb_subtrees")

      KerberosServer.setKdbvalue(
        "kdb_subtrees",
        Convert.to_string(UI.QueryWidget(Id(:id_kdb_subtrees), :Value))
      )

      i = Convert.to_boolean(UI.QueryWidget(Id(:sub), :Value))
      Builtins.y2milestone(
        "radiobutton val: %1",
        UI.QueryWidget(Id(:sub), :Value)
      )
      KerberosServer.setKdbvalue("kdb_sscope", i == true ? "sub" : "one")

      nil
    end

    # #################################################################################

    def get_adv_kdb_containerref
      Builtins.y2debug("calling get_adv_kdb_containerref")

      UI.ChangeWidget(
        Id(:id_kdb_containerref),
        :Value,
        KerberosServer.getKdbvalue("kdb_containerref")
      )

      nil
    end

    def set_adv_kdb_containerref
      Builtins.y2debug("calling set_adv_kdb_containerref")

      KerberosServer.setKdbvalue(
        "kdb_containerref",
        Convert.to_string(UI.QueryWidget(Id(:id_kdb_containerref), :Value))
      )

      nil
    end

    # #################################################################################

    def get_adv_kdb_maxtktlife
      Builtins.y2debug("calling get_adv_kdb_maxtktlife")

      t = KerberosServer.splitTime(KerberosServer.getKdbvalue("kdb_maxtktlife"))

      UI.ChangeWidget(
        Id(:id_kdb_maxtktlife_available),
        :Value,
        KerberosServer.getKdbvalue("kdb_maxtktlife") == "" ? false : true
      )


      UI.ChangeWidget(
        Id(:id_kdb_maxtktlife_days),
        :Value,
        Builtins.tointeger(Ops.get_string(t, 0, "0"))
      )
      UI.ChangeWidget(
        Id(:id_kdb_maxtktlife_time),
        :Value,
        Ops.get_string(t, 1, "01:00:00")
      )

      UI.ChangeWidget(
        Id(:id_kdb_maxtktlife_days),
        :Enabled,
        KerberosServer.getKdbvalue("kdb_maxtktlife") == "" ? false : true
      )
      UI.ChangeWidget(
        Id(:id_kdb_maxtktlife_time),
        :Enabled,
        KerberosServer.getKdbvalue("kdb_maxtktlife") == "" ? false : true
      )

      nil
    end

    def set_adv_kdb_maxtktlife
      Builtins.y2debug("calling set_adv_kdb_maxtktlife")

      if Convert.to_boolean(
          UI.QueryWidget(Id(:id_kdb_maxtktlife_available), :Value)
        ) == false
        KerberosServer.setKdbvalue("kdb_maxtktlife", "")
      else
        s = Builtins.tostring(
          Convert.to_integer(
            UI.QueryWidget(Id(:id_kdb_maxtktlife_days), :Value)
          )
        )
        s = Ops.add(s, " ")
        s = Ops.add(
          s,
          Convert.to_string(UI.QueryWidget(Id(:id_kdb_maxtktlife_time), :Value))
        )

        KerberosServer.setKdbvalue("kdb_maxtktlife", s)
      end

      nil
    end

    # #################################################################################

    def get_adv_kdb_maxrenewlife
      Builtins.y2debug("calling get_adv_kdb_maxrenewlife")

      t = KerberosServer.splitTime(
        KerberosServer.getKdbvalue("kdb_maxrenewlife")
      )

      UI.ChangeWidget(
        Id(:id_kdb_maxrenewlife_available),
        :Value,
        KerberosServer.getKdbvalue("kdb_maxrenewlife") == "" ? false : true
      )

      UI.ChangeWidget(
        Id(:id_kdb_maxrenewlife_days),
        :Value,
        Builtins.tointeger(Ops.get_string(t, 0, "0"))
      )
      UI.ChangeWidget(
        Id(:id_kdb_maxrenewlife_time),
        :Value,
        Ops.get_string(t, 1, "01:00:00")
      )

      UI.ChangeWidget(
        Id(:id_kdb_maxrenewlife_days),
        :Enabled,
        KerberosServer.getKdbvalue("kdb_maxrenewlife") == "" ? false : true
      )
      UI.ChangeWidget(
        Id(:id_kdb_maxrenewlife_time),
        :Enabled,
        KerberosServer.getKdbvalue("kdb_maxrenewlife") == "" ? false : true
      )

      nil
    end

    def set_adv_kdb_maxrenewlife
      Builtins.y2debug("calling set_adv_kdb_maxrenewlife")

      if Convert.to_boolean(
          UI.QueryWidget(Id(:id_kdb_maxrenewlife_available), :Value)
        ) == false
        KerberosServer.setKdbvalue("kdb_maxrenewlife", "")
      else
        s = Builtins.tostring(
          Convert.to_integer(
            UI.QueryWidget(Id(:id_kdb_maxrenewlife_days), :Value)
          )
        )
        s = Ops.add(s, " ")
        s = Ops.add(
          s,
          Convert.to_string(
            UI.QueryWidget(Id(:id_kdb_maxrenewlife_time), :Value)
          )
        )

        KerberosServer.setKdbvalue("kdb_maxrenewlife", s)
      end

      nil
    end

    # #################################################################################

    def get_adv_kdb_flags
      Builtins.y2debug("calling get_adv_kdb_flags")

      flags = KerberosServer.getKdbvalue("kdb_flags")

      UI.ChangeWidget(
        Id(:kdb_flags_allow_postdated),
        :Value,
        Builtins.issubstring(flags, "-allow_postdated") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_allow_forwardable),
        :Value,
        Builtins.issubstring(flags, "-allow_forwardable") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_allow_renewable),
        :Value,
        Builtins.issubstring(flags, "-allow_renewable") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_allow_proxiable),
        :Value,
        Builtins.issubstring(flags, "-allow_proxiable") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_allow_dup_skey),
        :Value,
        Builtins.issubstring(flags, "-allow_dup_skey") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_requires_preauth),
        :Value,
        Builtins.issubstring(flags, "+requires_preauth") ? true : false
      )
      UI.ChangeWidget(
        Id(:kdb_flags_requires_hwauth),
        :Value,
        Builtins.issubstring(flags, "+requires_hwauth") ? true : false
      )
      UI.ChangeWidget(
        Id(:kdb_flags_allow_svr),
        :Value,
        Builtins.issubstring(flags, "-allow_svr") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_allow_tgs_req),
        :Value,
        Builtins.issubstring(flags, "-allow_tgs_req") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_allow_tix),
        :Value,
        Builtins.issubstring(flags, "-allow_tix") ? false : true
      )
      UI.ChangeWidget(
        Id(:kdb_flags_needchange),
        :Value,
        Builtins.issubstring(flags, "+needchange") ? true : false
      )
      UI.ChangeWidget(
        Id(:kdb_flags_password_changing_service),
        :Value,
        Builtins.issubstring(flags, "+password_changing_service") ? true : false
      )

      nil
    end

    def set_adv_kdb_flags
      Builtins.y2debug("calling set_adv_kdb_flags")

      flags = ""

      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_allow_postdated), :Value)
        )
        flags = Ops.add(flags, "+allow_postdated ")
      else
        flags = Ops.add(flags, "-allow_postdated ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_allow_forwardable), :Value)
        )
        flags = Ops.add(flags, "+allow_forwardable ")
      else
        flags = Ops.add(flags, "-allow_forwardable ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_allow_renewable), :Value)
        )
        flags = Ops.add(flags, "+allow_renewable ")
      else
        flags = Ops.add(flags, "-allow_renewable ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_allow_proxiable), :Value)
        )
        flags = Ops.add(flags, "+allow_proxiable ")
      else
        flags = Ops.add(flags, "-allow_proxiable ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_allow_dup_skey), :Value)
        )
        flags = Ops.add(flags, "+allow_dup_skey ")
      else
        flags = Ops.add(flags, "-allow_dup_skey ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_requires_preauth), :Value)
        )
        flags = Ops.add(flags, "+requires_preauth ")
      else
        flags = Ops.add(flags, "-requires_preauth ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_requires_hwauth), :Value)
        )
        flags = Ops.add(flags, "+requires_hwauth ")
      else
        flags = Ops.add(flags, "-requires_hwauth ")
      end
      if Convert.to_boolean(UI.QueryWidget(Id(:kdb_flags_allow_svr), :Value))
        flags = Ops.add(flags, "+allow_svr ")
      else
        flags = Ops.add(flags, "-allow_svr ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_allow_tgs_req), :Value)
        )
        flags = Ops.add(flags, "+allow_tgs_req ")
      else
        flags = Ops.add(flags, "-allow_tgs_req ")
      end
      if Convert.to_boolean(UI.QueryWidget(Id(:kdb_flags_allow_tix), :Value))
        flags = Ops.add(flags, "+allow_tix ")
      else
        flags = Ops.add(flags, "-allow_tix ")
      end
      if Convert.to_boolean(UI.QueryWidget(Id(:kdb_flags_needchange), :Value))
        flags = Ops.add(flags, "+needchange ")
      else
        flags = Ops.add(flags, "-needchange ")
      end
      if Convert.to_boolean(
          UI.QueryWidget(Id(:kdb_flags_password_changing_service), :Value)
        )
        flags = Ops.add(flags, "+password_changing_service ")
      else
        flags = Ops.add(flags, "-password_changing_service ")
      end

      KerberosServer.setKdbvalue("kdb_flags", flags)

      nil
    end


    # #################################################################################

    def get_adv_itemlist
      generalItemList = []
      itemlist = []

      if KerberosServer.getDBtype == "file"
        # Treeview list item
        itemlist = Builtins.add(
          itemlist,
          Item(Id(:database_name), _("Database Path"))
        )
      end
      # Treeview list item
      itemlist = Builtins.add(itemlist, Item(Id(:acl_file), _("ACL File")))
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:admin_keytab), _("Administrator Keytab"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(
          Id(:default_principal_expiration),
          _("Default Principal Expiration")
        )
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:default_principal_flags), _("Default Principal Flags"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:dict_file), _("Dictionary File"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:kadmind_port), _("Kadmin Daemon Port"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:kpasswd_port), _("Kpasswd Daemon Port"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:key_stash_file), _("Key Stash File"))
      )
      # Treeview list item
      itemlist = Builtins.add(itemlist, Item(Id(:kdc_ports), _("KDC Port")))
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:master_key_name), _("Master Key Name"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:master_key_type), _("Master Key Type"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:max_life), _("Maximum Ticket Life Time"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:max_renewable_life), _("Maximum Ticket Renew Time"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:supported_enctypes), _("Default Encryption Types"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:kdc_supported_enctypes), _("KDC Supported Encryption Types"))
      )
      # Treeview list item
      itemlist = Builtins.add(
        itemlist,
        Item(Id(:reject_bad_transit), _("Reject Bad Transit"))
      )


      # 	  itemlist = add(itemlist, );
      # 	  itemlist = add(itemlist, );
      # 	  itemlist = add(itemlist, );

      # Treeview list item
      generalItemList = Builtins.add(
        generalItemList,
        Item(Id(:advanced), _("Advanced Settings"), true, itemlist)
      )

      if KerberosServer.getDBtype == "ldap"
        ldapitems = []

        # Treeview list item
        ldapitems = Builtins.add(
          ldapitems,
          Item(Id(:ldap_conns_per_server), _("Number of LDAP connections"))
        )
        # Treeview list item
        ldapitems = Builtins.add(
          ldapitems,
          Item(Id(:kdb_subtrees), _("Search Subtrees"))
        )
        # Treeview list item
        ldapitems = Builtins.add(
          ldapitems,
          Item(Id(:kdb_containerref), _("Principal Container"))
        )
        # Treeview list item
        ldapitems = Builtins.add(
          ldapitems,
          Item(Id(:kdb_maxtktlife), _("Maximum Ticket Life Time"))
        )
        # Treeview list item
        ldapitems = Builtins.add(
          ldapitems,
          Item(Id(:kdb_maxrenewlife), _("Maximum Ticket Renew Time"))
        )
        # Treeview list item
        ldapitems = Builtins.add(
          ldapitems,
          Item(Id(:kdb_flags), _("Default Principal Flags"))
        )
        # 		  ldapitems = add(ldapitems, );
        # 		  ldapitems = add(ldapitems, );
        # 		  ldapitems = add(ldapitems, );

        generalItemList = Builtins.add(
          generalItemList,
          Item(Id(:advldap), _("Advanced LDAP Settings"), true, ldapitems)
        )
      end

      deep_copy(generalItemList)
    end
  end
end
