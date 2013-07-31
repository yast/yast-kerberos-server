# encoding: utf-8

module Yast
  class KerberosServerClient < Client
    def main
      # testedfiles: KerberosServer.ycp

      Yast.include self, "testsuite.rb"
      TESTSUITE_INIT([], nil)

      Yast.import "KerberosServer"

      DUMP("KerberosServer::Modified")
      TEST(lambda { KerberosServer.Modified }, [], nil)

      nil
    end
  end
end

Yast::KerberosServerClient.new.main
