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

# File:	include/kerberos-server/helps.ycp
# Package:	Configuration of kerberos-server
# Summary:	Help texts of all the dialogs
# Authors:	Michael Calmer <mc@novell.com>
#
# $Id: helps.ycp 27914 2006-02-13 14:32:08Z locilka $
module Yast
  module KerberosServerHelpsInclude
    def initialize_kerberos_server_helps(include_target)
      textdomain "kerberos-server"

      # All helps are here
      @HELPS = {
        # Read dialog help 1/2
        "read"                             => _(
          "<p><b><big>Initializing Kerberos Server Configuration</big></b><br>\n</p>\n"
        ) +
          # Read dialog help 2/2
          _(
            "<p><b><big>Aborting Initialization:</big></b><br>\nSafely abort the configuration utility by pressing <b>Abort</b> now.</p>\n"
          ),
        # Write dialog help 1/2
        "write"                            => _(
          "<p><b><big>Saving Kerberos Server Configuration</big></b><br>\n</p>\n"
        ) +
          # Write dialog help 2/2
          _(
            "<p><b><big>Aborting Saving:</big></b><br>\n" +
              "Abort the save procedure by pressing <b>Abort</b>.\n" +
              "An additional dialog informs whether it is safe to do so.\n" +
              "</p>\n"
          ),
        # Help text: ask for database backend 1/4
        "AskDBtype"                        => _(
          "<p>Specify where the Kerberos server should store the data.</p>"
        ) +
          # Help text: ask for database backend 2/4
          _(
            "<p><big>Local Database</big> will create a local database for storing the credentials.</p>"
          ) +
          # Help text: ask for database backend 3/4
          _(
            "<p><big>Set Up New LDAP Server as Database Back-End</big> will set up a new LDAP server\non this machine and use it as database back-end.</p>\n"
          ) +
          # Help text: ask for database backend 4/4
          _(
            "<p><big>Use Existing LDAP Server as Database Back-End</big> gives you the\noption to use an external LDAP server as database back-end.</p>\n"
          ),
        # Help text: basic settings 1/2
        "basic"                            => _(
          "<p>Specify the <big>Realm</big> and the <big>Master Password</big> for your Kerberos server.</p>"
        ) +
          # Help text: basic settings 2/2
          _(
            "<p>Although your Kerberos realm can be any ASCII string, the convention is to use upper-case letters as in your domain name.</p>\n"
          ),
        # Help text: Use existing LDAP server 1/6
        "useldap"                          => _(
          "<p>In this dialog, edit some parameters for the LDAP server.</p>"
        ) +
          # Help text: Use existing LDAP server 2/6
          _(
            "<p>With <big>LDAP Server URI</big> specify the location of the LDAP\nserver. For example, <tt>ldaps://host.domain.com</tt>.</p>"
          ) +
          # Help text: Use existing LDAP server 3/6
          _(
            "<p>With <big>LDAP Base DN</big> you can change the base DN of the LDAP server.</p>"
          ) +
          # Help text: Use existing LDAP server 4/6
          _(
            "<p>The <big>Kerberos Container DN</big> specifies the container where the Kerberos server should create \nthe principals and other informational data by default.</p>"
          ) +
          # Help text: Use existing LDAP server 5/6
          _(
            "<p><big>KDC Bind DN</big> is the DN that KDC uses to authenticate to the LDAP server.\nOnly read access is required for this account.</p>\n"
          ) +
          # Help text: Use existing LDAP server 6/6
          _(
            "<p><big>Kadmin Bind DN</big> is the DN that Kadmind uses to authenticate to the LDAP server.\nThis account also needs write access.</p>\n"
          ),
        # Help text: New LDAP server 1/6
        "newldap"                          => _(
          "<p>In this dialog, edit some parameters to set up an LDAP server.</p>"
        ) +
          # Help text: New LDAP server 2/6
          _(
            "<p>With <big>LDAP Base DN</big> you can change the base DN of the LDAP server.</p>"
          ) +
          # Help text: New LDAP server 3/6
          _(
            "<p>The <big>Kerberos Container DN</big> specifies the container where the Kerberos server should create \nthe principals and other informational data by default.</p>\n"
          ) +
          # Help text: New LDAP server 4/6
          _("<p><big>KDC Bind DN</big> is the DN for the administrator.</p>") +
          # Help text: New LDAP server 5/6
          _(
            "<p>If you select the checkbox <big>Use Previously Entered Password</big>, the password you entered\nas the KDC Master password is also used for the LDAP administrator. \n"
          ) +
          # Help text: New LDAP server 6/6
          _(
            "When the checkbox is not set, you can enter a different password for the LDAP administrator.</p>"
          ),
        # Help text: Summary 1/3
        "summary"                          => _(
          "<p>This is a short summary about your Kerberos server configuration.</p>"
        ) +
          # Help text: Summary 2/3
          _(
            "<p>With the radio buttons you can enable or disable this service.</p>"
          ) +
          # Help text: Summary 3/3
          _(
            "<p>You can change some values of your configuration by clicking the <b>Edit</b> button.</p>"
          ),
        # ==============================================================================

        # advanced item help: database_name
        "adv_database_name"                => _(
          "<p>This string specifies the location of the Kerberos database for this realm.</p>"
        ),
        # advanced item help: acl_file
        "adv_acl_file"                     => _(
          "<p>This string specifies the location of the access control list (ACL) file that kadmin uses to determine the principals' permissions on the database.</p>"
        ),
        # advanced item help: admin_keytab
        "adv_admin_keytab"                 => _(
          "<p>This string specifies the location of the keytab file that kadmin uses to authenticate to the database.</p>"
        ),
        # advanced item help: default_principal_expiration
        "adv_default_principal_expiration" => _(
          "<p>This absolute time specifies the default expiration date of principals created in this realm.</p>"
        ),
        # advanced item help principal_flags 1/13
        "adv_default_principal_flags"      => _(
          "<p>These flags specify the default attributes of the principal created in this realm.</p>"
        ) + "<ul><li><b>" +
          _("Allow postdated") + "</b> " +
          # advanced item help principal_flags 2/13 :Allow postdated
          _(
            "Enabling this flag allows the principal to obtain postdateable tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow forwardable") + "</b> " +
          # advanced item help principal_flags 3/13 :Allow forwardable
          _(
            "Enabling this flag allows the principal to obtain forwardable tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow renewable") + "</b> " +
          # advanced item help principal_flags 4/13 :Allow renewable
          _(
            "Enabling this flag allows the principal to obtain renewable tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow proxiable") + "</b> " +
          # advanced item help principal_flags 5/13 :Allow proxiable
          _("Enabling this flag allows the principal to obtain proxy tickets.") + "</li>" + "<li><b>" +
          _("Enable user-to-user authentication") + "</b> " +
          # advanced item help principal_flags 6/13 :Enable user-to-user authentication
          _(
            "Enabling this flag allows the principal to obtain a session key for another user, permitting user-to-user authentication for this  principal."
          ) + "</li>" + "<li><b>" +
          _("Requires preauth") + "</b> " +
          # advanced item help principal_flags 7/13 :Requires preauth
          _(
            "If this flag is enabled on a client principal, that principal is required to preauthenticate to the KDC before receiving any tickets. If you enable this flag on a service principal, the service tickets for this principal will only be issued to clients with a TGT that has the preauthenticated ticket set."
          ) + "</li>" + "<li><b>" +
          _("Requires hwauth") + "</b> " +
          # advanced item help principal_flags 8/13 :Requires hwauth
          _(
            "If this flag is enabled, the principal is required to preauthenticate using a hardware device before receiving any tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow service") + "</b> " +
          # advanced item help principal_flags 9/13 :Allow service
          _(
            "Enabling this flag allows the KDC to issue service tickets for this principal."
          ) + "</li>" + "<li><b>" +
          _("Allow tgs request") + "</b> " +
          # advanced item help principal_flags 10/13 :Allow tgs request
          _(
            "Enabling this flag allows a principal to obtain tickets based on a ticket-granting-ticket, rather than repeating the authentication process that was used to obtain the TGT."
          ) + "</li>" + "<li><b>" +
          _("Allow tickets") + "</b> " +
          # advanced item help principal_flags 11/13 :Allow tickets
          _(
            "Enabling  this  flag  means  that the KDC will issue tickets for this principal. Disabling this flag essentially deactivates the principal within this realm."
          ) + "</li>" + "<li><b>" +
          _("Need change") + "</b> " +
          # advanced item help principal_flags 12/13 :Needchange
          _("Enabling this flag forces a password change for this principal.") + "</li>" + "<li><b>" +
          _("Password changing service") + "</b> " +
          # advanced item help principal_flags 13/13 :Password changing service
          _(
            "If this flag is enabled, it marks this principal as a password change service.  This should only be used in special cases, for example,  if a  user's  password  has  expired,  the user has to get tickets for that principal to be able to change it without going through the normal password authentication."
          ) + "</li></ul>",
        # advanced item help : dict_file
        "adv_dict_file"                    => _(
          "<p>The string location of the dictionary file containing strings that are not allowed as passwords. If this tag is not set or if there is no policy assigned to the principal, no check will be done.</p>"
        ),
        # advanced item help : kadmind_port
        "adv_kadmind_port"                 => _(
          "<p>This port number specifies the port on which the kadmind daemon listens for this realm.</p>"
        ),
        # advanced item help : kpasswd_port
        "adv_kpasswd_port"                 => _(
          "<p>This port number specifies the port on which the kadmind daemon listens for this realm.</p>"
        ),
        # advanced item help : key_stash_file
        "adv_key_stash_file"               => _(
          "<p>This string specifies the location where the master key has been stored with kdb5_stash.</p>"
        ),
        # advanced item help : kdc_ports
        "adv_kdc_ports"                    => _(
          "<p>This string specifies the list of ports that the KDC listens to for this realm.</p>"
        ),
        # advanced item help : master_key_name
        "adv_master_key_name"              => _(
          "<p>This string specifies the name of the principal associated with the master key. The default value is K/M.</p>"
        ),
        # advanced item help : master_key_type
        "adv_master_key_type"              => _(
          "<p>This key type string represents the master keys key type.</p>"
        ),
        # advanced item help : max_life
        "adv_max_life"                     => _(
          "<p>This delta time specifies the maximum time period that a ticket may be valid for in this realm.</p>"
        ),
        # advanced item help : max_renew_life
        "adv_max_renew_life"               => _(
          "<p>This delta time specifies the maximum time period that a ticket may be renewed for in this realm.</p>"
        ),
        # advanced item help : supported_enctypes
        "adv_supported_enctypes"           => _(
          "<p>A list of key/salt strings that specifies the default key/salt combinations of principals for this realm.</p>"
        ),
        # advanced item help : kdc_supported_enctypes
        "adv_kdc_supported_enctypes"       => _(
          "<p>Specifies the permitted key/salt combinations of principals for this realm.</p>"
        ),
        # advanced item help : reject_bad_transit
        "adv_reject_bad_transit"           => _(
          "<p>Specifies whether or not the list of transited realms for cross-realm tickets should be checked against the transit path computed from the realm names and the [capaths] section of its krb5.conf file</p>"
        ),
        # advanced item help : ldap_conns_per_server
        "adv_ldap_conns_per_server"        => _(
          "<p>This LDAP specific tag indicates the number of connections to be maintained via the LDAP server.</p>"
        ),
        # advanced item help : ldap_service_password_file
        "adv_ldap_service_password_file"   => _(
          "<p>This LDAP-specific tag indicates the file containing the stashed passwords for the objects used for starting the Kerberos servers.</p>"
        ),
        # advanced item help : kdb_subtrees
        "adv_kdb_subtrees"                 => _(
          "<p>Specifies the list of subtrees containing the principals of a realm. The list contains the DNs of the subtree objects separated by colon(:).</p><p>The search scope specifies the scope for searching the principals under the subtree.</p>"
        ),
        # advanced item help : kdb_containerref
        "adv_kdb_containerref"             => _(
          "<p>Specifies the DN of the container object in which the principals of a realm will be created. If the container reference is not configured for a realm, the principals will be created in the realm container.</p>"
        ),
        # advanced item help : kdb_maxtktlife
        "adv_kdb_maxtktlife"               => _(
          "<p>Specifies maximum ticket life for principals in this realm.</p>"
        ),
        # advanced item help : kdb_maxrenewlife
        "adv_kdb_maxrenewlife"             => _(
          "<p>Specifies maximum renewable life of tickets for principals in this realm.</p>"
        )
      } 

      # EOF
    end
  end
end
