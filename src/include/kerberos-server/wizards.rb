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
  module KerberosServerWizardsInclude
    def initialize_kerberos_server_wizards(include_target)
      textdomain "kerberos-server"

      Yast.import "Sequencer"
      Yast.import "Wizard"
      Yast.import "Package"

      Yast.include include_target, "kerberos-server/complex.rb"
    end

    # Main workflow of the kerberos-server configuration
    # @return sequence result
    def MainSequence
      aliases = { "summary" => lambda { SummaryDialog() }, "advanced" => lambda do
        AdvancedConfiguration(false)
      end }

      sequence = {
        "ws_start" => "summary",
        "summary"  => {
          :abort => :abort,
          :back  => :abort,
          :next  => :next,
          :edit  => "advanced"
        },
        "advanced" => {
          :abort => :abort,
          :next  => "summary",
          :back  => "summary"
        }
      }

      ret = Sequencer.Run(aliases, sequence)

      deep_copy(ret)
    end

    # Whole configuration of kerberos-server
    # @return sequence result
    def KerberosServerSequence
      aliases = {
        "read"       => lambda { ReadDialog() },
        "main"       => lambda { MainSequence() },
        "dbtype"     => lambda { AskDBtypeDialog() },
        "basicf"     => lambda { AskBasicDialog(true) },
        "basicli"    => lambda { AskBasicDialog(false) },
        "basiclu"    => lambda { AskBasicDialog(false) },
        "ldapinit"   => lambda { AskLdapDialog(true) },
        "ldapuse"    => lambda { AskLdapDialog(false) },
        "advancedf"  => lambda { AdvancedConfiguration(false) },
        "advancedli" => lambda { AdvancedConfiguration(true) },
        "advancedlu" => lambda { AdvancedConfiguration(true) },
        "write"      => lambda { WriteDialog() }
      }

      sequence = {
        "ws_start"   => "read",
        "read"       => {
          :abort => :abort,
          :next  => "main",
          :init  => "dbtype",
          :back  => :abort
        },
        "main"       => { :abort => :abort, :next => "write" },
        "dbtype"     => {
          :abort   => :abort,
          :file    => "basicf",
          :newldap => "basicli",
          :useldap => "basiclu",
          :back    => :abort
        },
        "basicf"     => {
          :abort    => :abort,
          :next     => "write",
          :back     => "dbtype",
          :advanced => "advancedf"
        },
        "basicli"    => {
          :abort    => :abort,
          :next     => "ldapinit",
          :back     => "dbtype",
          :advanced => "advancedli"
        },
        "basiclu"    => {
          :abort    => :abort,
          :next     => "ldapuse",
          :back     => "dbtype",
          :advanced => "advancedlu"
        },
        "ldapinit"   => {
          :abort    => :abort,
          :next     => "write",
          :back     => "basicli",
          :advanced => "advancedli"
        },
        "ldapuse"    => {
          :abort    => :abort,
          :next     => "write",
          :back     => "basiclu",
          :advanced => "advancedlu"
        },
        "advancedf"  => {
          :abort => :abort,
          :next  => "basicf",
          :back  => "basicf"
        },
        "advancedli" => {
          :abort => :abort,
          :next  => "ldapinit",
          :back  => "ldapinit"
        },
        "advancedlu" => {
          :abort => :abort,
          :next  => "ldapuse",
          :back  => "ldapuse"
        },
        "write"      => { :abort => :abort, :next => :next, :back => "main" }
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("kerberos-server")

      ret = Sequencer.Run(aliases, sequence)

      UI.CloseDialog
      deep_copy(ret)
    end

    # Whole configuration of kerberos-server but without reading and writing.
    # For use with autoinstallation.
    # @return sequence result
    def KerberosServerAutoSequence
      # Initialization dialog caption
      caption = _("Kerberos Server Configuration")
      # Initialization dialog contents
      contents = Label(_("Initializing..."))

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("kerberos-server")
      Wizard.SetContentsButtons(
        caption,
        contents,
        "",
        Label.BackButton,
        Label.NextButton
      )

      ret = MainSequence()

      UI.CloseDialog
      deep_copy(ret)
    end
  end
end
