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
  class KerberosServerClient < Client
    def main
      Yast.import "UI"

      #**
      # <h3>Configuration of kerberos-server</h3>

      textdomain "kerberos-server"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("KerberosServer module started")

      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Summary"

      Yast.import "CommandLine"
      Yast.include self, "kerberos-server/wizards.rb"

      @cmdline_description = {
        "id"         => "kerberos-server",
        # Command line help text for the Xkerberos-server module
        "help"       => _(
          "Configuration of Kerberos server"
        ),
        "guihandler" => fun_ref(method(:KerberosServerSequence), "any ()"),
        "initialize" => fun_ref(KerberosServer.method(:Read), "boolean ()"),
        "finish"     => fun_ref(KerberosServer.method(:Write), "boolean ()"),
        "actions" =>
          # FIXME TODO: fill the functionality description here
          {},
        "options" =>
          # FIXME TODO: fill the option descriptions here
          {},
        "mappings" =>
          # FIXME TODO: fill the mappings of actions and options here
          {}
      }

      # is this proposal or not?
      @propose = false
      @args = WFM.Args
      if Ops.greater_than(Builtins.size(@args), 0)
        if Ops.is_path?(WFM.Args(0)) && WFM.Args(0) == path(".propose")
          Builtins.y2milestone("Using PROPOSE mode")
          @propose = true
        end
      end

      # main ui function
      @ret = nil

      if @propose
        @ret = KerberosServerAutoSequence()
      else
        @ret = CommandLine.Run(@cmdline_description)
      end
      Builtins.y2debug("ret=%1", @ret)

      # Finish
      Builtins.y2milestone("KerberosServer module finished")
      Builtins.y2milestone("----------------------------------------")

      deep_copy(@ret) 

      # EOF
    end
  end
end

Yast::KerberosServerClient.new.main
