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
  module KerberosServerComplexInclude
    def initialize_kerberos_server_complex(include_target)
      textdomain "kerberos-server"

      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Wizard"
      Yast.import "Confirm"
      Yast.import "KerberosServer"
      Yast.import "CWMFirewallInterfaces"

      Yast.include include_target, "kerberos-server/helps.rb"
      Yast.include include_target, "kerberos-server/advanced_items.rb"
    end

    # Return a modification status
    # @return true if data was modified
    def Modified
      KerberosServer.Modified
    end

    def ReallyAbort
      !KerberosServer.Modified || Popup.ReallyAbort(true)
    end

    def PollAbort
      UI.PollInput == :abort
    end

    # Read settings dialog
    # @return `abort if aborted and `next otherwise
    def ReadDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "read", ""))
      # KerberosServer::AbortFunction = PollAbort;
      return :abort if !Confirm.MustBeRoot
      ret = KerberosServer.Read

      return :abort if !ret

      Builtins.y2milestone(
        "Wizard: found Database? : %1",
        KerberosServer.getFoundDB
      )

      return :init if KerberosServer.getFoundDB == false
      :next
    end

    # Write settings dialog
    # @return `abort if aborted and `next otherwise
    def WriteDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "write", ""))
      # KerberosServer::AbortFunction = PollAbort;
      ret = KerberosServer.Write
      if !ret &&
          Popup.YesNo(
            _("Saving the configuration failed. Change the settings?")
          )
        return :back
      end
      ret ? :next : :abort
    end


    def AskDBtypeDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "AskDBtype", ""))

      # caption
      caption = _("Select the Database Back-End")

      content = HBox(
        HSpacing(3),
        # Button group label
        Frame(
          _("Select the database back-end you want to use"),
          RadioButtonGroup(
            Id(:rb),
            VBox(
              # Checkbox text
              Left(RadioButton(Id(:file), Opt(:notify), _("&Local Database"))),
              # Checkbox text
              Left(
                RadioButton(
                  Id(:newldap),
                  Opt(:notify),
                  _("&Set up new LDAP server as database back-end")
                )
              ),
              # Checkbox text
              Left(
                RadioButton(
                  Id(:useldap),
                  Opt(:notify),
                  _("&Use existing LDAP server as database back-end")
                )
              )
            )
          )
        ),
        HSpacing(3)
      )

      Wizard.SetContentsButtons(
        caption,
        content,
        Ops.get_string(@HELPS, "AskDBtype", ""),
        Label.BackButton,
        Label.NextButton
      )

      ret = :file
      type = KerberosServer.getDBtype

      if type == nil || type == "" || type == "file"
        UI.ChangeWidget(Id(:file), :Value, true)
      elsif type == "ldap"
        if KerberosServer.getLdapUseExisting
          UI.ChangeWidget(Id(:useldap), :Value, true)
          ret = :useldap
        else
          UI.ChangeWidget(Id(:newldap), :Value, true)
          ret = :newldap
        end
      end

      while true
        ret = Convert.to_symbol(UI.UserInput)

        # abort?
        if ret == :abort || ret == :cancel || ret == :back
          if ReallyAbort()
            ret = :abort
            break
          else
            next
          end
        elsif ret == :file
          KerberosServer.setDBtype("file")
          KerberosServer.setDBvalue(
            "database_name",
            "/var/lib/kerberos/krb5kdc/principal"
          )
        elsif ret == :newldap || ret == :useldap
          KerberosServer.setDBtype("ldap")
          KerberosServer.setDBvalue("database_name", "")
          if ret == :newldap
            KerberosServer.setLdapUseExisting(false)
          else
            KerberosServer.setLdapUseExisting(true)
          end
        elsif ret == :next
          if Convert.to_boolean(UI.QueryWidget(Id(:file), :Value))
            KerberosServer.setDBtype("file")
            KerberosServer.setDBvalue(
              "database_name",
              "/var/lib/kerberos/krb5kdc/principal"
            )
            ret = :file
          elsif Convert.to_boolean(UI.QueryWidget(Id(:newldap), :Value))
            ret = :newldap
          elsif Convert.to_boolean(UI.QueryWidget(Id(:useldap), :Value))
            ret = :useldap
          else
            Builtins.y2error("unexpected selection.")
            next
          end
          Builtins.y2milestone("configuring kerberos database type: %1", ret)
          break
        else
          Builtins.y2error("unexpected retcode: %1", ret)
          next
        end
      end

      ret
    end


    def AskBasicDialog(adv)
      # caption
      caption = _("Basic Kerberos Settings")

      advButton = Empty()

      if adv
        # Button text
        advButton = PushButton(Id(:advanced), _("&Advanced Configuration"))
      end

      firewall_settings = {
        "services"        => ["service:kdc", "service:kadmind"],
        "display_details" => true
      }
      firewall_widget = CWMFirewallInterfaces.CreateOpenFirewallWidget(
        firewall_settings
      )


      content = HBox(
        HSpacing(3),
        VBox(
          VSpacing(0.5),
          # Frame lable
          Frame(
            _("Basic Kerberos Settings"),
            VBox(
              # TextEntry label: "Realm" is a typical kerberos phrase.
              # 								Please think twice please before you translate this,
              # 								and check with kerberos.pot how it is translated there.
              InputField(
                Id(:realm),
                Opt(:hstretch),
                _("R&ealm"),
                KerberosServer.getDBrealm
              ),
              Password(
                Id(:pw1),
                Opt(:hstretch),
                Label.Password,
                KerberosServer.getDBpassword
              ),
              Password(
                Id(:pw2),
                Opt(:hstretch),
                Label.ConfirmPassword,
                KerberosServer.getDBpassword
              )
            )
          ),
          advButton,
          VSpacing(1),
          # Frame label
          Frame(
            _("Firewall Settings"),
            Ops.get_term(firewall_widget, "custom_widget", Empty())
          )
        )
      )

      Wizard.SetContentsButtons(
        caption,
        content,
        Ops.get_string(@HELPS, "basic", ""),
        Label.BackButton,
        Label.NextButton
      )

      CWMFirewallInterfaces.OpenFirewallInit(firewall_widget, "")

      ret = nil
      event = {}

      while true
        event = UI.WaitForEvent
        ret = Ops.get_symbol(event, "ID")

        CWMFirewallInterfaces.OpenFirewallHandle(firewall_widget, "", event)

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back
          break
        elsif ret == :advanced || ret == :next
          CWMFirewallInterfaces.OpenFirewallStore(firewall_widget, "", event)

          stash = KerberosServer.getDBvalue("key_stash_file")
          oldrealm = KerberosServer.getDBrealm
          realm = Convert.to_string(UI.QueryWidget(Id(:realm), :Value))

          newstash = Builtins.regexpsub(
            stash,
            Ops.add(Ops.add("^(.+)", oldrealm), "$"),
            Ops.add("\\1", realm)
          )
          if newstash != nil
            KerberosServer.setDBvalue("key_stash_file", newstash)
          end

          # --------------------------------- password checks
          pw1 = Convert.to_string(UI.QueryWidget(Id(:pw1), :Value))
          pw2 = Convert.to_string(UI.QueryWidget(Id(:pw2), :Value))

          if pw1 != pw2
            # The two user password information do not match
            # error popup
            Report.Error(_("The passwords do not match.\nTry again."))
            UI.SetFocus(Id(:pw1))
            next
          end

          KerberosServer.setDBrealm(realm)
          KerberosServer.setDBpassword(pw1)

          if ret == :next && pw1 == ""
            # Error popup
            Report.Error(_("Empty password is not allowed."))
            UI.SetFocus(Id(:pw1))
            next
          end

          break
        else
          Builtins.y2error("unexpected retcode: %1", ret)
          next
        end
      end

      ret
    end

    def AskLdapDialog(init)
      # caption
      caption = _("Kerberos Setting for the LDAP Back-End")

      help = Ops.get_string(@HELPS, "useldap", "")

      if !init
        KerberosServer.ReadDefaultLdapValues
      else
        KerberosServer.CalcDefaultLdapValues
      end
      # TextEntry label
      ldapServerTl = InputField(
        Id(:server),
        Opt(:hstretch),
        _("LDAP &Server URI:"),
        KerberosServer.getLdapDBvalue("ldap_servers")
      )
      pwCheckbox1 = Empty()
      # TextEntry label
      kadmindnW = InputField(
        Id(:kadmin),
        Opt(:hstretch),
        _("K&admin Bind DN:"),
        KerberosServer.getLdapDBvalue("ldap_kadmind_dn")
      )
      kadminpw1 = HBox(
        Password(
          Id(:kadminpw1),
          Opt(:hstretch),
          Label.Password,
          KerberosServer.getLdapKadmPw
        ),
        HSpacing(3),
        Password(
          Id(:kadminpw2),
          Opt(:hstretch),
          Label.ConfirmPassword,
          KerberosServer.getLdapKadmPw
        )
      )

      if init
        help = Ops.get_string(@HELPS, "newldap", "")

        # when we init a new ldap server , we know the URI. No need to ask for it.
        ldapServerTl = Empty()

        kadmindnW = Empty()
        kadminpw1 = Empty()
        #kadminpw2 = `Empty();

        pwCheckbox1 = CheckBox(
          Id(:kdc_use_kdcpw),
          Opt(:notify),
          # Checkbox text
          _("Use prev&iously entered password"),
          true
        )
      end

      content = HBox(
        HSpacing(3),
        VBox(
          VSpacing(0.5),
          # Frame label
          Frame(
            _("LDAP Settings"),
            VBox(
              ldapServerTl, #kadminpw2
              # TextEntry label
              InputField(
                Id(:basedn),
                Opt(:hstretch),
                _("LDAP ba&se DN:"),
                KerberosServer.getLdapBaseDN
              ),
              # TextEntry label
              InputField(
                Id(:container),
                Opt(:hstretch),
                _("Kerberos &Container DN:"),
                KerberosServer.getLdapDBvalue("ldap_kerberos_container_dn")
              ),
              HBox(
                # TextEntry label
                InputField(
                  Id(:kdcadmin),
                  Opt(:hstretch),
                  _("K&DC Bind DN:"),
                  KerberosServer.getLdapDBvalue("ldap_kdc_dn")
                ),
                pwCheckbox1
              ),
              HBox(
                Password(
                  Id(:kdcpw1),
                  Opt(:hstretch),
                  Label.Password,
                  KerberosServer.getLdapKdcPw
                ),
                HSpacing(3),
                Password(
                  Id(:kdcpw2),
                  Opt(:hstretch),
                  Label.ConfirmPassword,
                  KerberosServer.getLdapKdcPw
                )
              ),
              kadmindnW,
              kadminpw1
            )
          ),
          # Button text
          PushButton(Id(:advanced), _("Ad&vanced Configuration"))
        )
      )


      Wizard.SetContentsButtons(
        caption,
        content,
        help,
        Label.BackButton,
        Label.NextButton
      )

      if init
        UI.ChangeWidget(Id(:kdcpw1), :Enabled, false)
        UI.ChangeWidget(Id(:kdcpw2), :Enabled, false)
      end

      ret = nil
      while true
        ret = Convert.to_symbol(UI.UserInput)

        # abort?
        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back
          break
        elsif ret == :kdc_use_kdcpw
          UI.ChangeWidget(
            Id(:kdcpw1),
            :Enabled,
            !Convert.to_boolean(UI.QueryWidget(Id(:kdc_use_kdcpw), :Value))
          )
          UI.ChangeWidget(
            Id(:kdcpw2),
            :Enabled,
            !Convert.to_boolean(UI.QueryWidget(Id(:kdc_use_kdcpw), :Value))
          )
        elsif ret == :next || ret == :advanced
          if init &&
              Convert.to_boolean(UI.QueryWidget(Id(:kdc_use_kdcpw), :Value))
            KerberosServer.setLdapKdcPw(KerberosServer.getDBpassword)
          else
            pw1 = Convert.to_string(UI.QueryWidget(Id(:kdcpw1), :Value))
            pw2 = Convert.to_string(UI.QueryWidget(Id(:kdcpw2), :Value))

            if pw1 != pw2
              # The two user password information do not match
              # error popup
              Report.Error(
                _("The LDAP KDC passwords do not match.\nTry again.")
              )
              UI.SetFocus(Id(:kdcpw1))
              next
            end
            KerberosServer.setLdapKdcPw(pw1)
          end

          if init
            KerberosServer.setLdapKadmPw(KerberosServer.getLdapKdcPw)
          else
            pw1 = Convert.to_string(UI.QueryWidget(Id(:kadminpw1), :Value))
            pw2 = Convert.to_string(UI.QueryWidget(Id(:kadminpw2), :Value))

            if pw1 != pw2
              # The two user password information do not match
              # error popup
              Report.Error(
                _("The LDAP Kadmin passwords do not match.\nTry again.")
              )
              UI.SetFocus(Id(:kadminpw1))
              next
            end
            KerberosServer.setLdapKadmPw(pw1)
          end

          if init
            KerberosServer.setLdapDBvalue("ldap_servers", "ldapi://")
          else
            KerberosServer.setLdapDBvalue(
              "ldap_servers",
              Convert.to_string(UI.QueryWidget(Id(:server), :Value))
            )
          end

          #KerberosServer::setDBtype("ldap");

          KerberosServer.setLdapBaseDN(
            Convert.to_string(UI.QueryWidget(Id(:basedn), :Value))
          )

          KerberosServer.setLdapDBvalue(
            "ldap_kerberos_container_dn",
            Convert.to_string(UI.QueryWidget(Id(:container), :Value))
          )
          KerberosServer.setLdapDBvalue(
            "ldap_kdc_dn",
            Convert.to_string(UI.QueryWidget(Id(:kdcadmin), :Value))
          )
          if init
            KerberosServer.setLdapDBvalue(
              "ldap_kadmind_dn",
              Convert.to_string(UI.QueryWidget(Id(:kdcadmin), :Value))
            )
          else
            KerberosServer.setLdapDBvalue(
              "ldap_kadmind_dn",
              Convert.to_string(UI.QueryWidget(Id(:kadmin), :Value))
            )
          end

          break
        else
          Builtins.y2error("unexpected retcode: %1", ret)
          next
        end
      end

      ret
    end


    def AdvancedConfiguration(ldap)
      itemList = get_adv_itemlist
      lastItem = nil

      # caption
      caption = _("Advanced Kerberos Configuration")

      # term content = `Label("Advanced Dialog");

      button = HBox(
        PushButton(Id(:back), Opt(:key_F8), Label.BackButton),
        HStretch(),
        PushButton(Id(:abort), Opt(:key_F9), Label.AbortButton),
        HStretch(),
        PushButton(Id(:next), Opt(:key_F10), Label.NextButton),
        Empty()
      )

      UI.OpenDialog(
        Opt(:defaultsize),
        VBox(
          VSpacing(3),
          HSpacing(85),
          HWeight(
            70,
            VBox(
              HBox(
                HWeight(
                  35,
                  # tree widget label
                  Tree(
                    Id(:tree),
                    Opt(:notify, :vstretch),
                    _("Advanced &Options"),
                    itemList
                  )
                ),
                HSpacing(1),
                HWeight(
                  65,
                  VBox(
                    HSpacing(60),
                    # label widget
                    Left(
                      Heading(
                        Id(:heading),
                        Opt(:hstretch),
                        _("Current Selection: ")
                      )
                    ),
                    VSpacing(0.5),
                    VBox(
                      ReplacePoint(
                        Id(:replace),
                        RichText(Id(:id_advanced_d), "")
                      )
                    )
                  )
                )
              ),
              button
            )
          )
        )
      )

      UI.ChangeWidget(Id(:tree), :CurrentItem, :advanced)
      lastItem = :advanced

      ret = :dummy

      while ret != :back && ret != :abort && ret != :next
        ret = Convert.to_symbol(UI.UserInput)

        if ret == :abort || ret == :cancel
          if ReallyAbort()
            break
          else
            next
          end
        elsif ret == :back
          break
        end

        selected = Convert.to_symbol(UI.QueryWidget(Id(:tree), :CurrentItem))

        # saving settings for old selection
        item = Ops.get_map(@itemMap, lastItem, {})
        function = Ops.get(item, "setCallback")
        error = ""
        if function != nil
          ret2 = Builtins.eval(function)
          error = Convert.to_string(ret2) if Ops.is_string?(ret2)
        end

        if error != nil && Ops.greater_than(Builtins.size(error), 0)
          Popup.Error(error)
          # set selection back
          UI.ChangeWidget(Id(:tree), :CurrentItem, lastItem)
        else
          if ret == :add
            selected2 = Convert.to_symbol(
              UI.QueryWidget(Id(:tree), :CurrentItem)
            )
            Builtins.y2milestone("Add for: %1", selected2)

            # Calling Add callback
            item2 = Ops.get_map(@itemMap, lastItem, {})
            function2 = Ops.get(item2, "addCallback")
            ret2 = Builtins.eval(function2) if function2 != nil
          elsif ret == :modify
            selected2 = Convert.to_symbol(
              UI.QueryWidget(Id(:tree), :CurrentItem)
            )
            Builtins.y2milestone("Modify for: %1", selected2)

            # Calling Modify callback
            item2 = Ops.get_map(@itemMap, lastItem, {})
            function2 = Ops.get(item2, "modifyCallback")
            ret2 = Builtins.eval(function2) if function2 != nil
          elsif ret == :delete
            selected2 = Convert.to_symbol(
              UI.QueryWidget(Id(:tree), :CurrentItem)
            )
            Builtins.y2milestone("Delete for: %1", selected2)

            # Calling Delete callback
            item2 = Ops.get_map(@itemMap, lastItem, {})
            function2 = Ops.get(item2, "deleteCallback")
            ret2 = Builtins.eval(function2) if function2 != nil
          else
            # no error --> goto next selection
            lastItem = selected
            item = Ops.get_map(@itemMap, selected, {})
            # header label
            UI.ChangeWidget(
              Id(:heading),
              :Value,
              Ops.add(
                _("Current Selection: "),
                Ops.get_string(item, "name", "")
              )
            )
            # showing concerning input fields
            UI.ReplaceWidget(
              Id(:replace),
              Ops.get_term(item, "widget", Empty())
            )

            # getting values
            function = Ops.get(item, "getCallback")
            ret2 = Builtins.eval(function) if function != nil
          end
        end
      end

      UI.CloseDialog

      ret
    end

    # Summary dialog
    # @return dialog result
    def SummaryDialog
      # KerberosServer summary dialog caption
      caption = _("Kerberos Server Configuration")

      summary = KerberosServer.Summary
      configured = Ops.get_string(summary, 0, "")

      firewall_settings = {
        "services"        => ["service:kdc", "service:kadmind"],
        "display_details" => true
      }
      firewall_widget = CWMFirewallInterfaces.CreateOpenFirewallWidget(
        firewall_settings
      )



      button = HBox(PushButton(Id(:edit), Label.EditButton), HStretch())

      # Frame label
      contents = VBox(
        VSpacing(0.5),
        RadioButtonGroup(
          Id(:rd),
          Left(
            HVSquash(
              VBox(
                # radio button label
                Left(
                  RadioButton(
                    Id(:disable),
                    Opt(:notify),
                    _("&Disable Kerberos"),
                    !KerberosServer.getServiceEnabled
                  )
                ),
                # radio button label
                Left(
                  RadioButton(
                    Id(:enable),
                    Opt(:notify),
                    _("&Enable Kerberos"),
                    KerberosServer.getServiceEnabled
                  )
                )
              )
            )
          )
        ),
        RichText(configured),
        button,
        VSpacing(1),
        # Frame label
        Frame(
          _("Firewall Settings"),
          Ops.get_term(firewall_widget, "custom_widget", Empty())
        )
      )

      Wizard.SetContentsButtons(
        caption,
        contents,
        Ops.get_string(@HELPS, "summary", ""),
        Label.BackButton,
        Label.FinishButton
      )

      UI.ChangeWidget(Id(:edit), :Enabled, KerberosServer.getServiceEnabled)

      CWMFirewallInterfaces.OpenFirewallInit(firewall_widget, "")

      ret = nil
      event = {}
      while true
        event = UI.WaitForEvent
        ret = Ops.get_symbol(event, "ID")

        CWMFirewallInterfaces.OpenFirewallHandle(firewall_widget, "", event)

        # abort?
        if ret == :abort || ret == :cancel || ret == :back
          if ReallyAbort()
            ret = :abort
            break
          else
            next
          end
        elsif ret == :edit || ret == :next
          CWMFirewallInterfaces.OpenFirewallStore(firewall_widget, "", event)
          break
        elsif ret == :enable
          KerberosServer.setServiceEnabled(true)
          UI.ChangeWidget(Id(:edit), :Enabled, true)
        elsif ret == :disable
          KerberosServer.setServiceEnabled(false)
          UI.ChangeWidget(Id(:edit), :Enabled, false)
        else
          Builtins.y2error("unexpected retcode: %1", ret)
          next
        end
      end
      ret
    end
  end
end
