#! /usr/bin/perl -w

# ------------------------------------------------------------------------------
# Copyright (c) 2006,2007 Novell, Inc. All Rights Reserved.
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

# File:		modules/KerberosServer.pm
# Package:	Configuration of kerberos-server
# Summary:	KerberosServer settings, input and output functions
# Authors:	Michael Calmer <mc@novell.com>
#
# $Id: $
#
# Representation of the configuration of kerberos-server.
# Input and output routines.


package KerberosServer;

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

use strict;

use ycp;
use YaST::YCP qw(Boolean sformat);

use YaPI;
use Data::Dumper;
use IPC::Open3;

textdomain("kerberos-server");

YaST::YCP::Import ("SCR");

# needed?
YaST::YCP::Import ("Kerberos");

YaST::YCP::Import ("Service");
YaST::YCP::Import ("Package");
YaST::YCP::Import ("Progress");
YaST::YCP::Import ("Report");
YaST::YCP::Import ("Summary");
YaST::YCP::Import ("Message");
YaST::YCP::Import ("Timezone");
YaST::YCP::Import ("Ldap");
YaST::YCP::Import ("URL");
YaST::YCP::Import ("SuSEFirewall");

our %TYPEINFO;

##
 # Data was modified?
 #
my $modified = 0;

##
 #
my $proposal_valid = 0;

##
 # Write only, used during autoinstallation.
 # Don't run services and SuSEconfig, it's all done at one place.
 #
my $write_only = 0;



##
 # Data was modified?
 # @return true if modified
 #
BEGIN { $TYPEINFO {Modified} = ["function", "boolean"]; }
sub Modified {
    y2debug ("modified=$modified");
    return Boolean($modified);
}


my $hostname = undef;

my $domain = undef;


################################################################

my $requiredObjectClasses = {
                             krbContainer => "2.16.840.1.113719.1.301.6.1.1",
                             krbRealmContainer => "2.16.840.1.113719.1.301.6.2.1",
                             krbPrincipalAux => "2.16.840.1.113719.1.301.6.8.1",
                             krbPrincipal => "2.16.840.1.113719.1.301.6.9.1",
                             krbPrincRefAux => "2.16.840.1.113719.1.301.6.11.1",
                             krbPwdPolicy => "2.16.840.1.113719.1.301.6.14.1",
                             krbTicketPolicyAux => "2.16.840.1.113719.1.301.6.16.1",
                             krbTicketPolicy => "2.16.840.1.113719.1.301.6.17.1"
                            };


################################################################

my $foundDB = 0;

# Was a database found during Read() ?
BEGIN { $TYPEINFO {getFoundDB} = ["function", "boolean"]; }
sub getFoundDB 
{
    return $foundDB;
}

################################################################

my $serviceEnabled = 0;

BEGIN { $TYPEINFO {getServiceEnabled} = ["function", "boolean"]; }
sub getServiceEnabled
{
    return $serviceEnabled;
}

BEGIN { $TYPEINFO {setServiceEnabled} = ["function", "void", "boolean"]; }
sub setServiceEnabled
{
    my $class = shift;

    $serviceEnabled = shift;
    $modified = 1;

    y2milestone("serviceEnabled: ".$serviceEnabled);
}


################################################################

my $dbtype = undef;

BEGIN { $TYPEINFO {getDBtype} = ["function", "string"]; }
sub getDBtype 
{
    if(defined $dbtype)
    {
        return $dbtype;
    }
    else
    {
        return "";
    }
}

BEGIN { $TYPEINFO {setDBtype} = ["function", "void", "string"]; }
sub setDBtype
{
    my $class = shift;
    $dbtype = shift;
    $modified = 1;
}

#################################################################
my $ldap_use_existing = 0;

BEGIN { $TYPEINFO {setLdapUseExisting} = ["function", "void", "boolean"]; }
sub setLdapUseExisting
{
    my $class = shift;
    $ldap_use_existing = shift;
    $modified = 1;
}

BEGIN { $TYPEINFO {getLdapUseExisting} = ["function", "boolean" ]; }
sub getLdapUseExisting
{
    my $class = shift;
    return Boolean($ldap_use_existing);
}

#################################################################

my $dbrealm = undef;

BEGIN { $TYPEINFO {getDBrealm} = ["function", "string"]; }
sub getDBrealm 
{
    if(defined $dbrealm)
    {
        return $dbrealm;
    }
    return "";
}

BEGIN { $TYPEINFO {setDBrealm} = ["function", "void", "string"]; }
sub setDBrealm
{
    my $class = shift;
    $dbrealm = shift;
    $modified = 1;
}

#################################################################

my $db = {};

BEGIN { $TYPEINFO {getDB} = ["function", ["map", "string", "string"]]; }
sub getDB 
{
    return $db;
}

BEGIN { $TYPEINFO {getDBvalue} = ["function", "string", "string"]; }
sub getDBvalue
{
    my $class = shift;
    my $key = shift;

    y2milestone("got request for key $key");
 
    if(exists $db->{$key} && defined $db->{$key})
    {
        return $db->{$key};
    }
    else
    {   
        return "";
    }
}

BEGIN { $TYPEINFO {setDB} = ["function", "void", ["map", "string", "string"]]; }
sub setDB 
{
    my $class = shift;
    $db = shift;
    $modified = 1;
}

BEGIN { $TYPEINFO {setDBvalue} = ["function", "void", "string", "string"]; }
sub setDBvalue
{
    my $class = shift;
    my $key   = shift;
    my $value = shift;

    y2milestone("set value $key = $value");
    
    $db->{$key} = $value;
    $modified = 1;
}

#################################################################

my $dbPassword = undef;

BEGIN { $TYPEINFO {getDBpassword} = ["function", "string"]; }
sub getDBpassword
{
    if(defined $dbPassword)
    {
        return $dbPassword;
    }
    return "";
}

BEGIN { $TYPEINFO {setDBpassword} = ["function", "void", "string"]; }
sub setDBpassword
{
    my $class = shift;
    $dbPassword = shift;
    $modified = 1;
}


#################################################################


# constant file database attributes - without database_name
my @fileDBattributes = (
                        "acl_file",
                        "admin_keytab",
                        "default_principal_expiration",
                        "default_principal_flags",
                        "dict_file",
                        "kadmind_port",
                        "kpasswd_port",
                        "key_stash_file",
                        "kdc_ports",
                        "master_key_name",
                        "master_key_type",
                        "max_life",
                        "max_renewable_life",
                        "supported_enctypes",
                        "kdc_supported_enctypes",
                        "reject_bad_transit"
                       );

BEGIN { $TYPEINFO {getFileDBattr} = ["function", ["list", "string"]]; }
sub getFileDBattr
{
    return \@fileDBattributes;
}

#################################################################

my $ldapkdcpw = "";

BEGIN { $TYPEINFO {getLdapKdcPw} = ["function", "string"]; }
sub getLdapKdcPw
{
    my $class = shift;
    return $ldapkdcpw;
}

BEGIN { $TYPEINFO {setLdapKdcPw} = ["function", "void", "string"]; }
sub setLdapKdcPw
{
    my $class = shift;
    $ldapkdcpw = shift;
    $modified = 1;
}

#################################################################

my $ldapkadmpw = "";

BEGIN { $TYPEINFO {getLdapKadmPw} = ["function", "string"]; }
sub getLdapKadmPw
{
    my $class = shift;
    return $ldapkadmpw;
}

BEGIN { $TYPEINFO {setLdapKadmPw} = ["function", "void", "string"]; }
sub setLdapKadmPw
{
    my $class = shift;
    $ldapkadmpw = shift;
    $modified = 1;
}



#################################################################

my $ldapdb = {};

BEGIN { $TYPEINFO {getLdapDB} = ["function", ["map", "string", "string"]]; }
sub getLdapDB
{
    my $class = shift;
    return $ldapdb;
}

BEGIN { $TYPEINFO {getLdapDBvalue} = ["function", "string", "string"]; }
sub getLdapDBvalue
{
    my $class = shift;
    my $key = shift;

    y2milestone("got ldap value request: $key");
    
    if(exists $ldapdb->{$key} && defined $ldapdb->{$key})
    {
        return $ldapdb->{$key};
    }
    else
    {   
        return "";
    }
}

BEGIN { $TYPEINFO {setLdapDB} = ["function", "void", ["map", "string", "string"]]; }
sub setLdapDB
{
    my $class = shift;
    $ldapdb = shift;
    $modified = 1;
}

BEGIN { $TYPEINFO {setLdapDBvalue} = ["function", "void", "string", "string"]; }
sub setLdapDBvalue
{
    my $class = shift;
    my $key = shift;
    my $val = shift;
    
    $ldapdb->{$key} = $val;
    $modified = 1;
}

#################################################################

my $ldapbasedn = "";

BEGIN { $TYPEINFO {getLdapBaseDN} = ["function", "string"]; }
sub getLdapBaseDN
{
    my $class = shift;
    return $ldapbasedn;
}

BEGIN { $TYPEINFO {setLdapBaseDN} = ["function", "void", "string"]; }
sub setLdapBaseDN
{
    my $class = shift;
    $ldapbasedn = shift;
    $modified = 1;
}


#################################################################

my $kdbvalues = {};

BEGIN { $TYPEINFO {getKdb} = ["function", ["map", "string", "string"]]; }
sub getKdb
{
    my $class = shift;
    return $kdbvalues;
}

BEGIN { $TYPEINFO {getKdbvalue} = ["function", "string", "string"]; }
sub getKdbvalue
{
    my $class = shift;
    my $key = shift;

    y2milestone("got kdb value request: $key");
    
    if(exists $kdbvalues->{$key} && defined $kdbvalues->{$key})
    {
        y2milestone("return $kdbvalues->{$key}");
        return $kdbvalues->{$key};
    }
    else
    {   
        return "";
    }
}

BEGIN { $TYPEINFO {setKdb} = ["function", "void", ["map", "string", "string"]]; }
sub setKdb
{
    my $class = shift;
    $kdbvalues = shift;
    $modified = 1;
}

BEGIN { $TYPEINFO {setKdbvalue} = ["function", "void", "string", "string"]; }
sub setKdbvalue
{
    my $class = shift;
    my $key = shift;
    my $val = shift;

    y2milestone("set kdb value : $key = $val");
    
    $kdbvalues->{$key} = $val;
    $modified = 1;
}

#################################################################

# constant ldap database attributes - without database_module and db_library
my @ldapDBattributes = (
                        "ldap_kerberos_container_dn",
                        "ldap_kdc_dn",
                        "ldap_kadmind_dn",
                        "ldap_service_password_file",
                        "ldap_server",
                        "ldap_conns_per_server",
                       );

BEGIN { $TYPEINFO {getLdapDBattr} = ["function", ["list", "string"]]; }
sub getLdapDBattr
{
    return \@ldapDBattributes;
}

#################################################################

# values saved inside of the ldap server, for kdb_ldap_util
my @kdbAttr = (
               "kdb_subtrees",
               "kdb_sscope",
               "kdb_containerref",
               "kdb_maxtktlife",
               "kdb_maxrenewlife",
               "kdb_flags"
              );

BEGIN { $TYPEINFO {getKdbAttr} = ["function", ["list", "string"]]; }
sub getKdbAttr
{
    return \@kdbAttr;
}


#################################################################


BEGIN { $TYPEINFO{splitTime} = ["function", ["list", "any"], "string"]; }
sub splitTime
{
    my $class = shift;
    my $string = shift;
    
    my $list = [];
    
    if($string =~ /(\d+\s)*(\d+):(\d+):(\d+)/)
    {
        if(defined $1)
        {
            push @{$list}, $1;
        }
        else
        {
            push @{$list}, 0;
        }
        push @{$list}, sprintf("%02d:%02d:%02d",$2, $3, $4);
    }
    else
    {
        push @{$list}, "0";
        push @{$list}, "01:00:00";
    }

    y2milestone("SplitTime: ".Data::Dumper->Dump([$list]));
    return $list;
}


BEGIN { $TYPEINFO{InstallPackages} = ["function", "boolean", ["list", "string"]]; }
sub InstallPackages
{
    my $class = shift;
    my $packages = shift;
    
    if(! Package->InstallAll($packages))
    {
        # translators: error popup before aborting the module
        Report->Error (_("YaST2 cannot continue the configuration
without installing the required packages."));
        return 0;
    }
    return 1
}


BEGIN { $TYPEINFO{CheckSchema} = ["function", "boolean", "void"]; }
sub CheckSchema
{
    my $class = shift;

    my $ret = $class->initLDAP();
    if(not $ret)
    {
        return $ret;
    }
    
    if(! SCR->Execute(".ldap.schema", {"schema_dn" => "cn=Subschema"}))
    {
        my $ldapERR = SCR->Read(".ldap.error");
        y2error("LDAP schema init failed:".$ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        return 0;
    }

    foreach my $key (keys %{$requiredObjectClasses})
    {
        my $schemaMap = SCR->Read(".ldap.schema.object_class", { "name" => $key });
        if(!defined $schemaMap)
        {
            my $ldapERR = SCR->Read(".ldap.error");
            y2error("LDAP readingschema failed:".$ldapERR->{'code'}." : ".$ldapERR->{'msg'});
            return 0;
        }
        
        y2milestone("SCHEMA MAP:".Data::Dumper->Dump([$schemaMap]));
        
        if(!exists $schemaMap->{oid} || !defined $schemaMap->{oid} || 
           $schemaMap->{oid} ne $requiredObjectClasses->{$key})
        {
            y2error("Kerberos Schema not known to the LDAP server.");
            return 0;
        }
    }    
    
    return 1;
}


BEGIN { $TYPEINFO{CreateDefaultCerts} = ["function", "boolean", "string"]; }
sub CreateDefaultCerts
{
    my $class = shift;
    my $passwd = $dbPassword;

    if(-e "/etc/ssl/servercerts/serverkey.pem")
    {
        # exists, no need to create a new one. Everything is fine.
        return 1;
    }
    

    if(! defined $passwd || $passwd eq "")
    {
        y2error("No password set");
        return 0;
    }
    
    require YaPI::CaManagement;
    
    
    my $data = {
                'certType' => 'ca'
               };
    
    my $certValueMap = YaPI::CaManagement->ReadCertificateDefaults($data);
    if( ! defined $certValueMap )
    {
        # error
        my $Yerr = YaPI::CaManagement->Error();
        y2error("Read Certificate Defaults failed: ".Data::Dumper->Dump([$Yerr]));
        return 0;
    }
    
    if(exists $certValueMap->{DN})
    {
        delete $certValueMap->{DN};
    }
    foreach (keys %{$certValueMap})
    {
        if( !defined $certValueMap->{$_})
        {
            delete $certValueMap->{$_};
        }
    }
    
    $certValueMap->{caName}      = "YaST_Default_CA";
    $certValueMap->{commonName}  = "YaST Default CA ($hostname.$domain)";
    $certValueMap->{countryName} = Timezone->GetCountryForTimezone("");
    $certValueMap->{emailAddress}= 'postmaster@'.$domain;
    $certValueMap->{keyPasswd}   = $passwd;
        
    y2milestone("Root CA Values: ".Data::Dumper->Dump([$certValueMap]));

    my $res = YaPI::CaManagement->AddRootCA($certValueMap);
    if( ! defined $res )
    {
        # error
        my $Yerr = YaPI::CaManagement->Error();
        y2error("Add Root CA failed: ".Data::Dumper->Dump([$Yerr]));
        return 0;
    }
    
    $data = {
             'caName'   => "YaST_Default_CA",
             'caPasswd' => $passwd,
             'certType' => 'server'
            };
    
    $certValueMap = YaPI::CaManagement->ReadCertificateDefaults($data);
    if( ! defined $certValueMap ) 
    {
        # error
        my $Yerr = YaPI::CaManagement->Error();
        y2error("Read Certificate Defaults failed: ".Data::Dumper->Dump([$Yerr]));
        return 0;
    }
    if(exists $certValueMap->{DN})
    {
        delete $certValueMap->{DN};
    }
    foreach (keys %{$certValueMap})
    {
        if( !defined $certValueMap->{$_})
        {
            delete $certValueMap->{$_};
        }
    }
    
    $certValueMap->{caName}      = "YaST_Default_CA";
    $certValueMap->{certType}    = "server";
    $certValueMap->{caPasswd}    = $passwd;
    $certValueMap->{keyPasswd}   = $passwd;
    $certValueMap->{commonName}  = "$hostname.$domain";
    $certValueMap->{countryName} = Timezone->GetCountryForTimezone("");
    $certValueMap->{emailAddress}= 'postmaster@'.$domain;

    y2milestone("Certificate Values: ".Data::Dumper->Dump([$certValueMap]));

    $res = YaPI::CaManagement->AddCertificate($certValueMap);
    if( ! defined $res )
    {
        # error
        my $Yerr = YaPI::CaManagement->Error();
        y2error("Add Certificate failed: ".Data::Dumper->Dump([$Yerr]));
        return 0;
    }
    
    $data = {
             caName          => "YaST_Default_CA",
             caPasswd        => $passwd,
             certificate     => $res,
             keyPasswd       => $passwd,
             exportFormat    => "PKCS12_CHAIN",
             destinationFile => "/tmp/YaST-Servercert.p12",
             P12Password     => $passwd
            };

    $res = YaPI::CaManagement->ExportCertificate ($data);
    if( ! defined $res )
    {
        # error
        my $Yerr = YaPI::CaManagement->Error();
        y2error("Export Certificate failed: ".Data::Dumper->Dump([$Yerr]));
        return 0;
    }
    
    $data = {
             passwd => $passwd,
             inFile => "/tmp/YaST-Servercert.p12"
            };
    
    $res = YaPI::CaManagement->ImportCommonServerCertificate($data);
    if( ! defined $res )
    {
        # error
        my $Yerr = YaPI::CaManagement->Error();
        y2error("Import Common Server Certificate failed: ".Data::Dumper->Dump([$Yerr]));
        unlink("/tmp/YaST-Servercert.p12");
        return 0;
    }
    unlink("/tmp/YaST-Servercert.p12");

    return 1;
}

BEGIN { $TYPEINFO{SetupLdapServer} = ["function", "boolean"]; }
sub SetupLdapServer
{
    my $class = shift;
    my $ret = 0;
    
    require LdapServer;
    require YaPI::LdapServer;
    
    $ret = LdapServer->Read();
    
    if(-e "/var/lib/ldap/__db.001")
    {
        y2error("Database exists. Cannot create a new one.");
        return 0;
    }
    my $directory = "/var/lib/ldap";


    # enable ldapi:// interface
    SCR->Write (".sysconfig.openldap.OPENLDAP_START_LDAPI", "yes");

    if (!SCR->Write (".sysconfig.openldap", undef))
    {
        y2error ("error writing /etc/sysconfig/openldap");
        return 0;
    }    

    my $data = {
                suffix => $ldapbasedn,
                rootdn => $class->getLdapDBvalue("ldap_kdc_dn"),
                passwd => $ldapkdcpw,
                directory => $directory,
                createdatabasedir => 1
               };
    $ret = LdapServer->AddDatabase($data);
    if(! $ret)
    {
        y2error("LdapServer => AddDatabase call failed");
        return 0;
    }
    
    if(! -e "/usr/share/doc/packages/krb5/kerberos.schema")
    {
        y2error("Kerberos schema file not found");
        return 0;
    }

    LdapServer->WriteLoglevel(256);
    
    my $schemas = LdapServer->ReadSchemaIncludeList();
    
    if( !grep( ($_ =~ /kerberos.schema/), @{$schemas}))
    {
        push @{$schemas}, "/usr/share/doc/packages/krb5/kerberos.schema";
        $ret = LdapServer->WriteSchemaIncludeList($schemas);
        if(! $ret)
        {
            y2error("LdapServer => WriteSchemaIncludeList call failed");
            return 0;
        }
    }
    
    $ret = LdapServer->WriteConfigureCommonServerCertificate(1);
    if(! $ret)
    {
        y2error("LdapServer => WriteConfigureCommonServerCertificate call failed");
        return 0;
    }

    $ret = LdapServer->WriteServiceEnabled(1);
    if(! $ret)
    {
        y2error("LdapServer => WriteServiceEnabled call failed");
        return 0;
    }
    
    $ret = LdapServer->Write();
    if(! $ret)
    {
        y2error("LdapServer => Write call failed");
        return 0;
    }
    

    $ret = YaPI::LdapServer->AddIndex( $ldapbasedn, {attr=>"krbPrincipalName",param=>"eq"} );
    if(!defined $ret)
    {
        my $err = YaPI::LdapServer->Error();
        y2error("AddIndex failed: ".Data::Dumper->Dump([$err]));
        return 0;
    }

    $ret = YaPI::LdapServer->RecreateIndex( $ldapbasedn );
    if(!defined $ret)
    {
        my $err = YaPI::LdapServer->Error();
        y2error("RecreateIndex failed: ".Data::Dumper->Dump([$err]));
        return 0;
    }

    if (!SCR->Write (".ldapserver.krb5ACLHack", "" ))
    {
        return undef;
    }
    YaPI::LdapServer->SwitchService(1);

    return 1;
}

BEGIN { $TYPEINFO{SetupLdapClient} = ["function", "void"]; }
sub SetupLdapClient
{
    my $class = shift;

    y2debug("SetupLdapClient: call Read");
    
    my $ret = Ldap->Read();
    if(! $ret)
    {
        y2error("LdapClient => Read call failed");
        return 0;
    }
    
    y2debug("SetupLdapClient: call Export");

    my $data = Ldap->Export();

    foreach (keys %{$data})
    {
        $data->{$_} = Boolean(1) if("$data->{$_}" eq "1");
        $data->{$_} = Boolean(0) if("$data->{$_}" eq "0");
    }

    if(exists $ldapdb->{ldap_server}  &&
       defined $ldapdb->{ldap_server} &&
       $ldapdb->{ldap_server} ne "")
    {
        my $uriParts = URL->Parse($ldapdb->{ldap_server});
        
        if($uriParts->{scheme} eq "ldapi")
        {
            # local ldap server; use hostname and domain 
            $data->{ldap_server} = "$hostname.$domain"; # == ldap server IP address or name
        }
        elsif(($uriParts->{scheme} eq "ldaps" || $uriParts->{scheme} eq "ldap") && $uriParts->{host} ne "")
        {
            # local ldap server; use hostname and domain 
            $data->{ldap_server} = $uriParts->{host}; # == ldap server IP address or name
        }
        else
        {
            y2error("Wrong LDAP URI: scheme ".$uriParts->{scheme}." not allowed");
            return 0;
        }
    }
    else
    {
        y2error("No LDAP server URI specified");
        return 0;
    }
    
    if(!exists $data->{base_config_dn}  ||
       !defined $data->{base_config_dn} ||
       $data->{base_config_dn} eq "")
    {
        $data->{base_config_dn} = "ou=ldapconfig,".$ldapbasedn;
    }
    
    $data->{ldap_domain}   = "$ldapbasedn"; # == basedn
    $data->{start_ldap}    = Boolean(1);
    #$data->{ldap_tls}      = Boolean(1);
    $data->{login_enabled} = Boolean(0);
    $data->{bind_dn}       = $ldapdb->{ldap_kadmind_dn}; # we use kadmin dn, because it needs write access
    $data->{create_ldap}   = Boolean(1);

    y2debug("SetupLdapClient: call Set with Data:".Data::Dumper->Dump([$data]));
    Ldap->Set($data);

    y2debug("SetupLdapClient: call SetBindPassword");
    Ldap->SetBindPassword($ldapkadmpw);

    y2debug("SetupLdapClient: call Write");
    $ret = Ldap->WriteNow();
    if(! $ret)
    {
        y2error("LdapClient => Write call failed");
        return 0;
    }
    return 1;
}

BEGIN { $TYPEINFO{SetupLdapBackend} = ["function", "boolean"]; }
sub SetupLdapBackend
{
    my $class = shift;
    my $ret = 0;
    
    $ret = SCR->Write(".krb5_conf.realms.\"$dbrealm\".kdc", ["$hostname.$domain"]);
    if(not $ret)
    {
        my $err = SCR->Error(".krb5_conf");
        #if($err->{code} eq "SCR_WRONG_PATH")
        #{
        #    next;
        #}
        y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
        return 0;
    }

    $ret = SCR->Write(".krb5_conf.realms.\"$dbrealm\".admin_server", ["$hostname.$domain"]);
    if(not $ret)
    {
        my $err = SCR->Error(".krb5_conf");
        #if($err->{code} eq "SCR_WRONG_PATH")
        #{
        #    next;
        #}
        y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
        return 0;
    }

    $ret = SCR->Write(".krb5_conf.realms.\"$dbrealm\".database_module", ["ldap"]);
    if(not $ret)
    {
        my $err = SCR->Error(".krb5_conf");
        #if($err->{code} eq "SCR_WRONG_PATH")
        #{
        #    next;
        #}
        y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
        return 0;
    }

    $ret = SCR->Write(".krb5_conf.dbmodules.ldap.db_library", ["kldap"]);
    if(not $ret)
    {
        my $err = SCR->Error(".krb5_conf");
        #if($err->{code} eq "SCR_WRONG_PATH")
        #{
        #    next;
        #}
        y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
        return 0;
    }
    
    # we need to set the default_realm in krb5.conf
    $ret = SCR->Write(".krb5_conf.libdefaults.default_realm", [$dbrealm]);
    if(not $ret)
    {
        my $err = SCR->Error(".krb5_conf");
        #if($err->{code} eq "SCR_WRONG_PATH")
        #{
        #    next;
        #}
        y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
        return 0;
    }
    
    $ret = $class->WriteKrb5Conf();
    if(not $ret)
    {
        return 0;
    }    

    $ret = $class->WriteKdcConf();
    if(not $ret)
    {
        return 0;
    }

    my @cmdArgs = ();
    push @cmdArgs, "-D", $ldapdb->{ldap_kadmind_dn};
    push @cmdArgs, "-H", $ldapdb->{ldap_server};
    push @cmdArgs, "create";
    push @cmdArgs, "-sf", $db->{key_stash_file}, "-s";
    push @cmdArgs, "-r", $dbrealm;
    
    if($class->getKdbvalue("kdb_subtrees") ne "")
    {
        push @cmdArgs, "-subtrees", $class->getKdbvalue("kdb_subtrees");

        my $scope = $class->getKdbvalue("kdb_sscope");
        $scope = "sub" if($scope ne "sub" || $scope ne "one");
        push @cmdArgs, "-sscope", $scope;
    }
    if($class->getKdbvalue("kdb_containerref") ne "")
    {
        push @cmdArgs, "-containerref", $class->getKdbvalue("kdb_containerref");
    }
    if($class->getKdbvalue("kdb_maxtktlife") ne "")
    {
        push @cmdArgs, "-maxtktlife", $class->toKdb5UtilTime($class->getKdbvalue("kdb_maxtktlife"));
    }
    if($class->getKdbvalue("kdb_maxrenewlife") ne "")
    {
        push @cmdArgs, "-maxrenewlife", $class->toKdb5UtilTime($class->getKdbvalue("kdb_maxrenewlife"));
    }
    
    # Must be last
    if($class->getKdbvalue("kdb_flags") ne "")
    {
        push @cmdArgs, split(/ /, $class->getKdbvalue("kdb_flags"));
    }
    
    y2milestone("Command: /usr/lib/mit/sbin/kdb5_ldap_util ".join(" ",@cmdArgs));

    my $pid = open3(\*IN, \*OUT, \*ERR, "/usr/lib/mit/sbin/kdb5_ldap_util", @cmdArgs)
    or do {
        y2error("Can not execute kdb5_ldap_util: $!");
        return 0;
    };
    
    print IN "$ldapkadmpw\n";   # LDAP Administrator Password
    print IN "$dbPassword\n";   # stash password
    print IN "$dbPassword\n";   # verify stash password
    
    close IN;
    my $out = "";
    my $err = "";
    while (<OUT>)
    {
        $out .= "$_";
    }
    while (<ERR>)
    {
        $err .= "$_";
    }
    close OUT;
    close ERR;
    waitpid $pid, 0;
    chomp($out) if(defined $out && $out ne "");
    if(defined $err && $err ne "")
    {
        chomp($err);
        y2error("Error during kdb5_ldap_util call: $err");
    }
    my $code = ($?>>8);
    if($code != 0)
    {
        return 0;
    }
    

    @cmdArgs = ();
    push @cmdArgs, "stashsrvpw";
    push @cmdArgs, "-f", $ldapdb->{ldap_service_password_file};
    push @cmdArgs, $ldapdb->{ldap_kdc_dn};
    
    y2milestone("Command: /usr/lib/mit/sbin/kdb5_ldap_util ".join(" ",@cmdArgs));

    $pid = open3(\*IN, \*OUT, \*ERR, "/usr/lib/mit/sbin/kdb5_ldap_util", @cmdArgs)
    or do {
        y2error("Can not execute kdb5_ldap_util: $!");
        return 0;
    };
    
    
    print IN "$ldapkdcpw\n";   # ldap kdc password
    print IN "$ldapkdcpw\n";   # verify ldap kdc password
    
    close IN;

    $out = "";
    $err = "";
    while (<OUT>)
    {
        $out .= "$_";
    }
    while (<ERR>)
    {
        $err .= "$_";
    }
    close OUT;
    close ERR;
    waitpid $pid, 0;
    chomp($out) if(defined $out && $out ne "");
    if(defined $err && $err ne "")
    {
        chomp($err);
        y2error("Error during kdb5_ldap_util call: $err");
    }
    $code = ($?>>8);
    if($code != 0)
    {
        return 0;
    }
    

    if($ldapdb->{ldap_kadmind_dn} ne $ldapdb->{ldap_kdc_dn})
    {
        pop @cmdArgs;
        push @cmdArgs, $ldapdb->{ldap_kadmind_dn};

        y2milestone("Command: /usr/lib/mit/sbin/kdb5_ldap_util ".join(" ",@cmdArgs));
        
        $pid = open3(\*IN, \*OUT, \*ERR, "/usr/lib/mit/sbin/kdb5_ldap_util", @cmdArgs)
        or do {
            y2error("Can not execute kdb5_ldap_util: $!");
            return 0;
        };
                
        print IN "$ldapkadmpw\n";   # ldap kadmin password
        print IN "$ldapkadmpw\n";   # verify ldap kadmin password
        
        close IN;

        $out = "";
        $err = "";
        while (<OUT>)
        {
            $out .= "$_";
        }
        while (<ERR>)
        {
            $err .= "$_";
        }
        close OUT;
        close ERR;
        waitpid $pid, 0;
        chomp($out) if(defined $out && $out ne "");
        if(defined $err && $err ne "")
        {
            chomp($err);
            y2error("Error during kdb5_ldap_util call: $err");
        }
        $code = ($?>>8);
        if($code != 0)
        {
            return 0;
        }
    }
    return 1;
}


BEGIN { $TYPEINFO{CalcDefaultLdapValues} = ["function", "void"]; }
sub CalcDefaultLdapValues
{
    my $class = shift;
    
    if(!exists $ldapdb->{ldap_kerberos_container_dn} &&
       !exists $ldapdb->{ldap_kdc_dn} &&
       !exists $ldapdb->{ldap_kadmind_dn} &&
       $ldapbasedn eq "")
    {
        $ldapbasedn = "dc=".join(",dc=", split(/\./, $domain));
        $ldapdb->{ldap_kerberos_container_dn} = "cn=krbcontainer,".$ldapbasedn;
        $ldapdb->{ldap_kdc_dn} = "cn=Administrator,".$ldapbasedn;
        $ldapdb->{ldap_kadmind_dn} = "cn=Administrator,".$ldapbasedn;
    }
}

BEGIN { $TYPEINFO{ReadDefaultLdapValues} = ["function", "void"]; }
sub ReadDefaultLdapValues
{
    my $class = shift;

    if(Ldap->Read()) 
    {
        my $ldapMap = Ldap->Export();
            
        if(!exists $ldapdb->{ldap_server} || !defined $ldapdb->{ldap_server} || $ldapdb->{ldap_server} eq "")
        {
            if(defined $ldapMap->{'ldap_server'} && $ldapMap->{'ldap_server'} ne "") 
            {
                my $dummy = $ldapMap->{'ldap_server'};
                
                $ldapdb->{ldap_server} = "ldaps://".Ldap->GetFirstServer("$dummy");
            }
        }            
        
        if($ldapbasedn eq "")
        {
            if($ldapMap->{'ldap_domain'} ne "")
            {
                $ldapbasedn = $ldapMap->{'ldap_domain'};
            }
            else
            {
                $ldapbasedn = "dc=".join(",dc=", split(/\./, $domain));
            }
        }
        
        if(!exists $ldapdb->{ldap_kerberos_container_dn})
        {
            $ldapdb->{ldap_kerberos_container_dn} = "cn=krbcontainer,".$ldapbasedn;
        }
        
        if(!exists $ldapdb->{ldap_kdc_dn})
        {
            if($ldapMap->{'bind_dn'} ne "")
            {
                $ldapdb->{ldap_kdc_dn} = $ldapMap->{'bind_dn'};
            }
            else
            {
                $ldapdb->{ldap_kdc_dn} = "cn=Administrator,".$ldapbasedn;
            }
        }
        
        if(!exists $ldapdb->{ldap_kadmind_dn})
        {
            if($ldapMap->{'bind_dn'} ne "")
            {
                $ldapdb->{ldap_kadmind_dn} = $ldapMap->{'bind_dn'};
            }
            else
            {
                $ldapdb->{ldap_kadmind_dn} = "cn=Administrator,".$ldapbasedn;
            }
        }
    }
}


sub initLDAP
{
    my $class = shift;
    
    if(!exists $ldapdb->{ldap_kadmind_dn} ||
       !defined $ldapdb->{ldap_kadmind_dn} ||
       $ldapdb->{ldap_kadmind_dn} eq "")
    {
        y2error("No bind DN available");
        return 0;
    }
    
    my $use_tls = "try";
    my $ldapMap = {};

    Ldap->Read(); 

    if(exists $ldapdb->{ldap_server} && defined $ldapdb->{ldap_server} && $ldapdb->{ldap_server} ne "")
    {
        y2milestone("initLDAP: found ldap_server $ldapdb->{ldap_server}");
        
        my $uriParts = URL->Parse($ldapdb->{ldap_server});

        if($uriParts->{scheme} eq "ldapi")
        {
            # local ldap server; use hostname and domain
            $ldapMap->{ldap_server} = "$hostname.$domain"; # == ldap server IP address or name
        }
         elsif(($uriParts->{scheme} eq "ldaps" || $uriParts->{scheme} eq "ldap") && $uriParts->{host} ne "")
         {
             # local ldap server; use hostname and domain
             $ldapMap->{ldap_server} = $uriParts->{host}; # == ldap server IP address or name
             $ldapMap->{ldap_port} = $uriParts->{port};
         }
         else
         {
             y2error("Wrong LDAP URI: scheme ".$uriParts->{scheme}." not allowed");
             return 0;
         }

         if(!exists $ldapMap->{ldap_port} || !defined $ldapMap->{ldap_port} || $ldapMap->{ldap_port} eq "")
         {
             # ldaps on 636 is not supported by the ldap agent
             $ldapMap->{ldap_port} = 389;
         }
    }     
   
    if (! SCR->Execute(".ldap", {"hostname" => $ldapMap->{'ldap_server'},
                                 "port"     => $ldapMap->{'ldap_port'},
                                 "use_tls"  => $use_tls })) 
    {
        y2error("LDAP initialization failed.");
        return 0;
    }
    
    if(!defined $ldapkadmpw || $ldapkadmpw eq "")
    {
        # change the bindDN temporarily
        my $old_bind_dn = $ldapMap->{bind_dn};
        
        $ldapMap->{bind_dn} = $ldapdb->{ldap_kadmind_dn};
        Ldap->Set($ldapMap);
        
        $ldapkadmpw = Ldap->LDAPAskAndBind(Boolean(0));

        $ldapMap->{bind_dn} = $old_bind_dn;
        Ldap->Set($ldapMap);
    }
    else
    {
        # bind; we have the password
        if(! SCR->Execute(".ldap.bind", { "bind_dn" => $ldapdb->{ldap_kadmind_dn},
                                          "bind_pw" => $ldapkadmpw}))
        {
            my $ldapERR = SCR->Read(".ldap.error");
            y2error("LDAP bind failed.(".$ldapERR->{'code'}.") : ".$ldapERR->{'msg'});
            return 0;
        }
    }
    
    return 1;
}


BEGIN { $TYPEINFO{ReadAttributesFromLDAP} = ["function", "boolean"]; }
sub ReadAttributesFromLDAP
{
    my $class = shift;

    if($foundDB != 1 || !defined $dbtype || $dbtype ne "ldap")
    {
        # no db or not ldap nothing to read here
        return 1;
    }
    
    my $ret = $class->initLDAP();
    if(not $ret)
    {
        return $ret;
    }
    
    my $attr = SCR->Read(".ldap.search", {
                                          "base_dn" => $ldapdb->{ldap_kerberos_container_dn},
                                          "filter" => "(& (objectclass=krbRealmContainer)(objectclass=krbTicketPolicyAux)(cn=$dbrealm))",
                                          "scope" => 2,
                                          "attrs" => [ "krbSubTrees", "krbSearchScope", "krbPrincContainerRef",
                                                       "krbMaxRenewableAge", "krbMaxTicketLife", "krbTicketFlags"]
                                         });
    if (! defined $attr)
    {
        my $ldapERR = SCR->Read(".ldap.error");
        y2error("Error while searching in LDAP.(".$ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        return 0;
    }

    my $attributes = {};
    
    if(exists $attr->[0] && defined $attr->[0] && ref($attr->[0]) eq "HASH")
    {
        # we expect only one object 
        $attributes = $attr->[0];
    }
    else
    {
        # no attributes found
        y2milestone("No attributes found in LDAP");
        return 1;
    }

    if(exists $attributes->{krbsubtrees} && defined $attributes->{krbsubtrees})
    {
        $kdbvalues->{kdb_subtrees} = join(":", @{$attributes->{krbsubtrees}});
    }
    if(exists $attributes->{krbsearchscope} && defined $attributes->{krbsearchscope} &&
       exists $attributes->{krbsearchscope}->[0] && defined $attributes->{krbsearchscope}->[0])
    {
        if($attributes->{krbsearchscope}->[0] eq "1")
        {
            $kdbvalues->{kdb_sscope} = "one";
        }
        else
        {
            $kdbvalues->{kdb_sscope} = "sub";
        }
    }
    if(exists $attributes->{krbprinccontainerref} && defined $attributes->{krbprinccontainerref} &&
       exists $attributes->{krbprinccontainerref}->[0] && defined $attributes->{krbprinccontainerref} &&
       $attributes->{krbprinccontainerref} ne "")
    {
        $kdbvalues->{kdb_containerref} = $attributes->{krbprinccontainerref};
    }
    if(exists $attributes->{krbmaxrenewableage} && defined $attributes->{krbmaxrenewableage} &&
       exists $attributes->{krbmaxrenewableage}->[0] && defined $attributes->{krbmaxrenewableage}->[0] &&
       $attributes->{krbmaxrenewableage}->[0] ne "")
    {
        my $dur = $attributes->{krbmaxrenewableage}->[0];
        
        my ($sec,$min,$hour,$days);
        
        $days = int($dur / (60*60*24));
        $dur = $dur % (60*60*24);

        $hour = int($dur / (60*60));
        $dur = $dur % (60*60);

        $min = int($dur / (60));
        $sec = $dur % (60);

        $kdbvalues->{kdb_maxrenewlife} = sprintf("%d %02d:%02d:%02d", $days, $hour, $min, $sec);
    }
    if(exists $attributes->{krbmaxticketlife} && defined $attributes->{krbmaxticketlife} &&
       exists $attributes->{krbmaxticketlife}->[0] && defined $attributes->{krbmaxticketlife}->[0] &&
       $attributes->{krbmaxticketlife}->[0] ne "")
    {
        my $dur = $attributes->{krbmaxticketlife}->[0];
        my ($sec,$min,$hour,$days);
        
        $days = int($dur / (60*60*24));
        $dur = $dur % (60*60*24);

        $hour = int($dur / (60*60));
        $dur = $dur % (60*60);

        $min = int($dur / (60));
        $sec = $dur % (60);
        
        $kdbvalues->{kdb_maxtktlife} = sprintf("%d %02d:%02d:%02d", $days, $hour, $min, $sec);
    }
    if(exists $attributes->{krbticketflags} && defined $attributes->{krbticketflags} &&
       exists $attributes->{krbticketflags}->[0] && defined $attributes->{krbticketflags}->[0] &&
       $attributes->{krbticketflags}->[0] ne "")
    {
        my $flags = $attributes->{krbticketflags}->[0];
   
        $kdbvalues->{kdb_flags} = $class->num2flags($flags);
    }
    
    return 1;
}

BEGIN { $TYPEINFO{ReadDatabase} = ["function", "boolean"]; }
sub ReadDatabase
{
    my $class = shift;
    
    $foundDB = 0;
    
    my $realms = SCR->Dir(".kdc_conf.section.realms");

    foreach my $realm (@{$realms})
    {
        my $db_names = SCR->Read(".kdc_conf.realms.\"$realm\".database_name");
        if(defined $db_names)
        {
            if(exists $db_names->[0] && defined  $db_names->[0] && 
               $db_names->[0] ne "" && -e "$db_names->[0]")
            {
                $foundDB = 1;
                
                $dbtype = "file";
                $dbrealm = $realm;
                $db->{database_name} = $db_names->[0];
                
                foreach my $attr (@fileDBattributes)
                {
                    my $vals = SCR->Read(".kdc_conf.realms.\"$realm\".$attr");
                    if(defined $vals && exists $vals->[0] && defined $vals->[0] && $vals->[0] ne "")
                    {
                        if($attr eq "max_life" || $attr eq "max_renewable_life")
                        {
                            $db->{$attr} = $class->encodeTime($vals->[0]);
                        }
                        else
                        {
                            $db->{$attr} = $vals->[0];
                        }
                    }
                }
                last;
            }
            else
            {
                $foundDB = 0;
                
                $dbtype  = undef;
                $dbrealm = $realm;
                
                foreach my $attr (@fileDBattributes)
                {
                    my $vals = SCR->Read(".kdc_conf.realms.\"$realm\".$attr");
                    if(defined $vals && exists $vals->[0] && defined $vals->[0] && $vals->[0] ne "")
                    {
                        if($attr eq "max_life" || $attr eq "max_renewable_life")
                        {
                            $db->{$attr} = $class->encodeTime($vals->[0]);
                        }
                        else
                        {
                            $db->{$attr} = $vals->[0];
                        }
                    }
                }

            }
        }
    }
    if(!$foundDB)
    {
        # search for LDAP DB

        $realms = SCR->Dir(".krb5_conf.section.realms");

        foreach my $realm (@{$realms})
        {
            my $db_names = SCR->Read(".krb5_conf.realms.\"$realm\".database_module");
            if(! defined $db_names)
            {
                y2milestone("UNDEF: ".Data::Dumper->Dump([SCR->Error(".krb5_conf")]));
            }
            else
            {
                if(exists $db_names->[0] && defined  $db_names->[0] && 
                   $db_names->[0] ne "" )
                {
                    my $db_module = SCR->Read(".krb5_conf.dbmodules.\"$db_names->[0]\".db_library");
                    if(defined $db_module && exists $db_module->[0] && 
                       defined $db_module->[0] && $db_module->[0] eq "kldap")
                    {
                        $foundDB = 1;
                        $dbtype = "ldap";
                        $dbrealm = $realm;

                        $ldapdb->{database_module} = $db_names->[0];
                        $ldapdb->{db_library} = "kldap";
                        
                        foreach my $attr (@ldapDBattributes)
                        {
                            my $vals = SCR->Read(".krb5_conf.dbmodules.\"$db_names->[0]\".$attr");
                            if(defined $vals && exists $vals->[0] && defined $vals->[0] && $vals->[0] ne "")
                            {
                                $ldapdb->{$attr} = $vals->[0];
                            }
                        }
                        # we need also the database attributes from kdc.conf for $realm
                        foreach my $attr (@fileDBattributes)
                        {
                            my $vals = SCR->Read(".kdc_conf.realms.\"$realm\".$attr");
                            if(defined $vals && exists $vals->[0] && defined $vals->[0] && $vals->[0] ne "")
                            {
                                if($attr eq "max_life" || $attr eq "max_renewable_life")
                                {
                                    $db->{$attr} = $class->encodeTime($vals->[0]);
                                }
                                else
                                {
                                    $db->{$attr} = $vals->[0];
                                }
                            }
                        }
                        $class->ReadAttributesFromLDAP();

                        last;
                    }
                }
            }
        }
    }
    
    if(! $foundDB )
    {
        if(defined $dbrealm && $dbrealm ne "")
        {
            # Seems we have an example configuration without DB
            # remove this example realm from kdc.conf and krb5.conf
            
            my $ret = SCR->Write(".kdc_conf.realms.\"$dbrealm\"", undef);
            if(not $ret)
            {
                my $err = SCR->Error(".kdc_conf");
                y2error("Error on writing to kdc.conf:".Data::Dumper->Dump([$err]));
            }
            $ret = SCR->Write(".kdc_conf", undef);
            if(not $ret)
            {
                my $err = SCR->Error(".kdc_conf");
                y2error("Error on writing to kdc.conf:".Data::Dumper->Dump([$err]));
            }
            $ret = SCR->Write(".krb5_conf.realms.\"$dbrealm\"", undef);
            if(not $ret)
            {
                my $err = SCR->Error(".krb5_conf");
                y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
            }
            $ret = SCR->Write(".krb5_conf", undef);
            if(not $ret)
            {
                my $err = SCR->Error(".krb5_conf");
                y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
            }
        }
        # check for if some defaults are available. If not, set them

        if(! defined $dbrealm || $dbrealm eq "" || $dbrealm eq "EXAMPLE.COM")
        {
            if(defined $domain && $domain ne "")
            {
                $dbrealm = uc($domain);
                $db->{key_stash_file} = "/var/lib/kerberos/krb5kdc/.k5.$dbrealm";
            }
            else
            {
                $dbrealm = "EXAMPLE.COM";
            }
        }
        if(! exists $db->{key_stash_file} ||
           ! defined $db->{key_stash_file} ||
           $db->{key_stash_file} eq "")
        {
            $db->{key_stash_file} = "/var/lib/kerberos/krb5kdc/.k5.$dbrealm";
        }
        if(! exists $db->{kdc_ports} ||
           ! defined $db->{kdc_ports} ||
           $db->{kdc_ports} eq "")
        {
            $db->{kdc_ports} = "750,88";
        }
        if(! exists $db->{max_life} ||
           ! defined $db->{max_life} ||
           $db->{max_life} eq "")
        {
            $db->{max_life} = "10h 0m 0s";
        }
        if(! exists $db->{max_renewable_life} ||
           ! defined $db->{max_renewable_life} ||
           $db->{max_renewable_life} eq "")
        {
            $db->{max_renewable_life} = "7d 0h 0m 0s";
        }
    }

    y2milestone("Found database: ".(($foundDB)?"true":"false"));
    if($foundDB)
    {
        y2milestone("DBtype: $dbtype  DBrealm: $dbrealm");
        y2milestone("File Args:".Data::Dumper->Dump([$db]));
        y2milestone("LDAP Args:".Data::Dumper->Dump([$ldapdb]));
    }
    
    return 1;
}

sub WriteKrb5Conf
{
    my $ret = 0;
    
    foreach my $attr (@ldapDBattributes)
    {
        my $val = undef;

        if(exists $ldapdb->{$attr} &&
           defined $ldapdb->{$attr} &&
           $ldapdb->{$attr} ne "")
        {
            $ret = SCR->Write(".krb5_conf.dbmodules.ldap.$attr", [$ldapdb->{$attr}]);
        }
        elsif($attr eq "ldap_service_password_file")
        {
            if(!exists $ldapdb->{ldap_service_password_file} ||
               !defined $ldapdb->{ldap_service_password_file} ||
               $ldapdb->{ldap_service_password_file} eq "")
            {
                # we need this; set a default
                $ldapdb->{ldap_service_password_file} = "/etc/openldap/ldap-pw";
            }
            
            $ret = SCR->Write(".krb5_conf.dbmodules.ldap.$attr", [$ldapdb->{$attr}]);
        }
        else
        {
            $ret = SCR->Write(".krb5_conf.dbmodules.ldap.$attr", undef);
        }
        if(not $ret)
        {
            my $err = SCR->Error(".krb5_conf");
            #if($err->{code} eq "SCR_WRONG_PATH")
            #{
            #    next;
            #}
            y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([$err]));
            return 0;
        }
    }

    $ret = SCR->Write(".krb5_conf", undef);
    if(not $ret)
    {
        y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([SCR->Error(".krb5_conf")]));
        return 0;
    }
    return $ret;
}


sub WriteKdcConf
{
    my $class = shift;
    
    my $ret = 0;
    
    foreach my $attr (@fileDBattributes)
    {
        my $val = undef;
        if(exists $db->{$attr} &&
           defined $db->{$attr} &&
           $db->{$attr} ne "")
        {
            if($attr eq "max_life" || $attr eq "max_renewable_life") 
            {
                $ret = SCR->Write(".kdc_conf.realms.\"$dbrealm\".$attr", [$class->decodeTime($db->{$attr})]);
            }
            else
            {
                $ret = SCR->Write(".kdc_conf.realms.\"$dbrealm\".$attr", [$db->{$attr}]);
            }
        }
        else
        {
            $ret = SCR->Write(".kdc_conf.realms.\"$dbrealm\".$attr", undef);
        }
        if(not $ret)
        {
            my $err = SCR->Error(".kdc_conf");
            if($err->{code} eq "SCR_WRONG_PATH")
            {
                next;
            }
            y2error("Error on writing to kdc.conf:".Data::Dumper->Dump([$err]));
            return 0;
        }
    }
    $ret = SCR->Write(".kdc_conf", undef);
    if(not $ret)
    {
        y2error("Error on writing to kdc.conf:".Data::Dumper->Dump([SCR->Error(".kdc_conf")]));
        return 0;
    }
    return $ret;
}


BEGIN { $TYPEINFO{ModifyLdapEntries} = ["function", "boolean"]; }
sub ModifyLdapEntries
{
    my $class = shift;

    if($foundDB != 1 || !defined $dbtype || $dbtype ne "ldap")
    {
        # no db or not ldap nothing to read here
        return 1;
    }

    if(!exists $ldapdb->{ldap_kadmind_dn} ||
       !defined $ldapdb->{ldap_kadmind_dn} ||
       $ldapdb->{ldap_kadmind_dn} eq "")
    {
        y2error("No bind DN available");
        return 0;
    }

    my @reset = ();

    my @cmdArgs = ();
    push @cmdArgs, "-D", $ldapdb->{ldap_kadmind_dn};
    push @cmdArgs, "-H", $ldapdb->{ldap_server};
    push @cmdArgs, "modify";
    push @cmdArgs, "-r", $dbrealm;

    if($class->getKdbvalue("kdb_subtrees") ne "")
    {
        push @cmdArgs, "-subtrees", $class->getKdbvalue("kdb_subtrees");

        my $scope = $class->getKdbvalue("kdb_sscope");
        $scope = "sub" if($scope ne "sub" || $scope ne "one");
        push @cmdArgs, "-sscope", $scope;
    }
    else
    {
        push @reset, "krbSubTrees", "krbSearchScope";
    }
    if($class->getKdbvalue("kdb_containerref") ne "")
    {
        push @cmdArgs, "-containerref", $class->getKdbvalue("kdb_containerref");
    }
    else
    {
        push @reset, "krbPrincContainerRef";
    }
    if($class->getKdbvalue("kdb_maxtktlife") ne "")
    {
        push @cmdArgs, "-maxtktlife", $class->toKdb5UtilTime($class->getKdbvalue("kdb_maxtktlife"));
    }
    else
    {
        push @reset, "krbMaxTicketLife";
    }
    if($class->getKdbvalue("kdb_maxrenewlife") ne "")
    {
        push @cmdArgs, "-maxrenewlife", $class->toKdb5UtilTime($class->getKdbvalue("kdb_maxrenewlife"));
    }
    else
    {
        push @reset, "krbMaxRenewableAge";
    }

    # Must be last
    if($class->getKdbvalue("kdb_flags") ne "")
    {
        push @cmdArgs, split(/ /, $class->getKdbvalue("kdb_flags"));
    }

    y2milestone("Command: /usr/lib/mit/sbin/kdb5_ldap_util ".join(" ",@cmdArgs));
    
    my $pid = open3(\*IN, \*OUT, \*ERR, "/usr/lib/mit/sbin/kdb5_ldap_util", @cmdArgs)
    or do {
        y2error("Can not execute kdb5_ldap_util: $!");
        return 0;
    };

    print IN "$ldapkadmpw\n";   # LDAP Administrator Password
    
    close IN;

    my $out = "";
    my $err = "";
    while (<OUT>)
    {
        $out .= "$_";
    }
    while (<ERR>)
    {
        $err .= "$_";
    }
    close OUT;
    close ERR;
    waitpid $pid, 0;
    chomp($out) if(defined $out && $out ne "");
    if(defined $err && $err ne "")
    {
        chomp($err);
        y2error("Error during kdb5_ldap_util call: $err");
    }
    my $code = ($?>>8);
    if($code != 0)
    {
        return 0;
    }
    
    # do we have to reset some values? 
    # We have to do it directly with LDAP until kdb5_ldap_util supports it.

    if($#reset >= 0)
    {
        my $ret = $class->initLDAP();
        if(not $ret)
        {
            return $ret;
        }

        foreach my $attribute (@reset)
        {
            my $DNs = SCR->Read(".ldap.search", {
                                                 "base_dn" => $ldapdb->{ldap_kerberos_container_dn},
                                                 "filter" => "(& (objectclass=krbRealmContainer)(objectclass=krbTicketPolicyAux)(cn=$dbrealm)($attribute=*))",
                                                 "scope" => 2,
                                                 "attrs" => [$attribute],
                                                 "dn_only" => 1
                                                });
            if(! defined $DNs)
            {
                my $ldapERR = SCR->Read(".ldap.error");
                y2error("Error while searching in LDAP.(".$ldapERR->{'code'}.") : ".$ldapERR->{'msg'});
                return 0;
            }
            if(@$DNs == 1)
            {
                my $entry = {
                             $attribute => ""
                            };
                if (not SCR->Write(".ldap.modify",
                                   { dn => $DNs->[0] } , $entry))
                {
                    my $ldapERR = SCR->Read(".ldap.error");
                    y2error("Error while deleting attribute ($attribute) in LDAP.(".$ldapERR->{'code'}.") : ".$ldapERR->{'msg'});
                }
            }        
        }
    }
    
    return 1;
}


BEGIN { $TYPEINFO{WriteDatabase} = ["function", "boolean"]; }
sub WriteDatabase
{
    my $class = shift;
    
    my $ret = 0;
    
    if(!$modified)
    {
        return 1;
    }
    
    if(! defined $dbrealm || $dbrealm eq "" ||
       ! defined $dbtype  || $dbtype  eq "")
    {
        y2error("No realm or dbtype set");
        return 0;
    }
    

    # initial setup
    if($foundDB == 0) 
    {
        if($dbtype eq "file")
        {
            if(! exists $db->{database_name} || !defined $db->{database_name} ||
               $db->{database_name} eq "")
            {
                y2error("no database name set");
                return 0;
            }
            
            $ret = SCR->Write(".kdc_conf.realms.\"$dbrealm\".database_name", [$db->{database_name}]);
            if(not $ret)
            {
                y2error("Error on writing to kdc.conf:".Data::Dumper->Dump([SCR->Error(".kdc_conf")]));
                return 0;
            }
            
            $ret = $class->WriteKdcConf();
            if(not $ret)
            {
                return 0;
            }

            # we need to set the default_realm in krb5.conf
            $ret = SCR->Write(".krb5_conf.libdefaults.default_realm", [$dbrealm]);
            if(not $ret)
            {
                y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([SCR->Error(".krb5_conf")]));
                return 0;
            }
            $ret = SCR->Write(".krb5_conf", undef);
            if(not $ret)
            {
                y2error("Error on writing to krb5.conf:".Data::Dumper->Dump([SCR->Error(".krb5_conf")]));
                return 0;
            }

            my @cmdArgs = ("create", "-r", "$dbrealm", "-s");

            y2milestone("Command: /usr/lib/mit/sbin/kdb5_ldap_util ".join(" ",@cmdArgs));

            my $pid = open3(\*IN, \*OUT, \*ERR, "/usr/lib/mit/sbin/kdb5_util", @cmdArgs)
            or do {
                y2error("Can not execute kdb5_util: $!");
                return 0;
            };
            
            print IN "$dbPassword\n";
            print IN "$dbPassword\n";
            
            close IN;

            my $out = "";
            my $err = "";
            while (<OUT>)
            {
                $out .= "$_";
            }
            while (<ERR>)
            {
                $err .= "$_";
            }
            close OUT;
            close ERR;
            waitpid $pid, 0;
            chomp($out) if(defined $out && $out ne "");
            if(defined $err && $err ne "")
            {
                chomp($err);
                y2error("Error during kdb5_ldap_util call: $err");
            }
            my $code = ($?>>8);
            if($code != 0)
            {
                return 0;
            }

    
            $ret = 1;
        }
        elsif($dbtype eq "ldap")
        {
            my $reqPackages = Ldap->UpdatedArchPackages(["pam_ldap", "nss_ldap"]);
            push @{$reqPackages}, "krb5-plugin-kdb-ldap";
            
            if(!$ldap_use_existing &&
               exists $ldapdb->{ldap_server} &&
               defined $ldapdb->{ldap_server} &&
               $ldapdb->{ldap_server} eq "ldapi://")
            {
                push @{$reqPackages}, "yast2-ldap-server", "yast2-ca-management", "openldap2";
                
                $ret = $class->InstallPackages($reqPackages);
                if(!$ret)
                {
                    return $ret;
                }

                y2milestone("Call CreateDefaultCerts");
                $ret = $class->CreateDefaultCerts();
                if(!$ret)
                {
                    return $ret;
                }
                
                y2milestone("Call SetupLdapServer");
                $ret = $class->SetupLdapServer();
                if(!$ret)
                {
                    return $ret;
                }

                y2milestone("Call SetupLdapClient");
                $ret = $class->SetupLdapClient();
                if(!$ret)
                {
                    return $ret;
                }
            }
            else
            {
                $ret = $class->InstallPackages($reqPackages);
                if(!$ret)
                {
                    return $ret;
                }

                y2milestone("Call CheckSchema");
                $ret = $class->CheckSchema();
                if(!$ret)
                {
                    return $ret;
                }
            }

            y2milestone("Call SetupLdapBackend");
            $ret = $class->SetupLdapBackend();
            if(!$ret)
            {
                return $ret;
            }
        }
        else
        {
            y2error("currently not supported");
            return 0;
        }

        Service->Adjust("krb5kdc", "enable");
        Service->RunInitScript ("krb5kdc", "start");
        
        Service->Adjust("kadmind", "enable");
        Service->RunInitScript ("kadmind", "start");
    }
    # modify database
    else
    {
        $ret = $class->WriteKdcConf();
        if(not $ret)
        {
            return 0;
        }
    
        if($dbtype eq "ldap")
        {
            $ret = $class->WriteKrb5Conf();
            if(not $ret)
            {
                return 0;
            }
            
            $ret = $class->ModifyLdapEntries();
            if(not $ret)
            {
                return 0;
            }
        }
            
        if(Service->Status("krb5kdc") == 0 && getServiceEnabled())
        {
            Service->Adjust("krb5kdc", "enable");
            Service->RunInitScript ("krb5kdc", "restart");
        }
        elsif(getServiceEnabled())
        {
            Service->Adjust("krb5kdc", "enable");
            Service->RunInitScript ("krb5kdc", "start");
        }
        else
        {
            Service->Adjust("krb5kdc", "disable");
            Service->RunInitScript ("krb5kdc", "stop");
        }
    
        if(Service->Status("kadmind") == 0 && getServiceEnabled())
        {
            Service->Adjust("kadmind", "enable");
            Service->RunInitScript ("kadmind", "restart");
        }
        elsif(getServiceEnabled())
        {
            Service->Adjust("kadmind", "enable");
            Service->RunInitScript ("kadmind", "start");
        }
        else
        {
            Service->Adjust("kadmind", "disable");
            Service->RunInitScript ("kadmind", "stop");
        }
        
        $ret = 1;
    }
    
    return $ret;
}


##
 # Read all kerberos-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Read} = ["function", "boolean"]; }
sub Read 
{
    my $class = shift;
    
    y2milestone("Read called");
    

    # KerberosServer read dialog caption
    my $caption = __("Initializing kerberos-server Configuration");

    my $steps = 2;

    my $sl = 0.5;
    sleep($sl);

    # We do not set help text here, because it was set outside
    Progress->New( $caption, " ", $steps, [
                                           # Progress stage 1/3
                                           __("Checking for required packages"),
                                           # Progress stage 2/3
                                           __("Read the database"),
                                          ], [
                                              # Progress step 1/3
                                              __("Checking for required packages..."),
                                              # Progress step 2/3
                                              __("Reading the database..."),
                                             ],
                   ""
                 );

    # install packages
    Progress->NextStage();

    my $ret = $class->InstallPackages([ "krb5-server", "krb5-client"]);
    if(! $ret)
    {
        return 0;
    }
    sleep($sl);

    # Read database
    Progress->NextStep();

    if(Service->Enabled("krb5kdc"))
    {
        $serviceEnabled = 1;
    }
    else
    {
        $serviceEnabled = 0;
    }
    
    $hostname = `/bin/hostname`;
    if($?)
    {
        y2error("Cannot read hostname");
        return 0;
    }
    chomp($hostname);
    
    $domain = `/bin/hostname --domain`;
    if($?)
    {
        y2error("Cannot read domain");
        return 0;
    }
    chomp($domain);

    my $progress_orig = Progress->set(0);
    SuSEFirewall->Read();
    Progress->set($progress_orig);

    $ret = $class->ReadDatabase();
    if(!$ret)
    {
        return $ret;
    }
    
    # Error message
    if(0)
    {
	Report::Error(__("Cannot read the database2."));
    }
    sleep($sl);

    $modified = 0;
    return Boolean(1);
}

##
 # Write all kerberos-server settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Write} = ["function", "boolean"]; }
sub Write 
{
    my $class = shift;

    y2milestone("Write called");

    # KerberosServer read dialog caption
    my $caption = __("Saving kerberos-server Configuration");

    my $steps = 2;

    my $sl = 1.0;
    sleep($sl);

    # We do not set help text here, because it was set outside
    Progress->New($caption, " ", $steps, [
	    # Progress stage 1/2
	    __("Write Firewall settings"),
	    # Progress stage 2/2
	    __("Write Kerberos settings"),
	], [
	    # Progress step 1/2
	    __("Writing Firewall settings..."),
	    # Progress step 2/2
	    __("Writing Kerberos settings..."),
	    # Progress finished
	    __("Finished")
       ],
       ""
    );

    # Write Firewall settings
    Progress->NextStage();

    my $progress_orig = Progress->set(0);
    SuSEFirewall->Write();
    Progress->set($progress_orig);

    sleep($sl);
    
    # write Kerberos settings
    Progress->NextStage();

    my $ret = $class->WriteDatabase();
    
    # Error message
    if(not $ret)
    {
        return $ret;
    }
    sleep($sl);
    
    # Progress finished
    Progress->NextStage();
    sleep($sl);
    
    return Boolean($ret);
}

##
 # Get all kerberos-server settings from the first parameter
 # (For use by autoinstallation.)
 # @param settings The YCP structure to be imported.
 # @return boolean True on success
 #
BEGIN { $TYPEINFO{Import} = ["function", "boolean", [ "map", "any", "any" ] ]; }
sub Import {
    my %settings = %{$_[0]};
    # TODO FIXME: your code here (fill the above mentioned variables)...
    return Boolean(1);
}

##
 # Dump the kerberos-server settings to a single map
 # (For use by autoinstallation.)
 # @return map Dumped settings (later acceptable by Import ())
 #
BEGIN { $TYPEINFO{Export}  =["function", [ "map", "any", "any" ] ]; }
sub Export {
    # TODO FIXME: your code here (return the above mentioned variables)...
    return {};
}

##
 # Create a textual summary and a list of unconfigured cards
 # @return summary of the current configuration
 #
BEGIN { $TYPEINFO{Summary} = ["function", [ "list", "string" ] ]; }
sub Summary {
    
    # summary text - title
    my $sum = "<h1>".__("Configuration of the Kerberos Server")."</h1><br>";

    $sum .= "<table>";

    # summary text 
    $sum .= "<tr><td>".__("Database Backend: ")."</td><td>".$dbtype."</td></tr>";
    if(exists $db->{database_name} && defined $db->{database_name})
    {
        # summary text 
        $sum .="<tr><td>".__("Database Name:")."</td><td>".$db->{database_name}."</td></tr>";
    }
    
    # summary text 
    $sum .= "<tr><td>".__("Realm: ")."</td><td>".$dbrealm."</td></tr>";
    
    if(exists $db->{kdc_ports} && defined $db->{kdc_ports} && $db->{kdc_ports} ne "")
    {
        # summary text 
        $sum .= "<tr><td>". __("KDC Ports:")."</td><td>".$db->{kdc_ports}."</td></tr>";
    }
    if(exists $db->{kadmind_port} && defined $db->{kadmind_port} && $db->{kadmind_port} ne "")
    {
        # summary text 
        $sum .= "<tr><td>".__("kadmind Port:")."</td><td>".$db->{kadmind_port}."</td></tr>";
    }
    if(exists $db->{kpasswd_port} && defined $db->{kpasswd_port} && $db->{kpasswd_port} ne "")
    {
        # summary text 
        $sum .= "<tr><td>".__("kpasswd Port:")."</td><td>".$db->{kpasswd_port}."</td></tr>";
    }

    if($dbtype eq "ldap")
    {
        # summary text 
        $sum .= "<tr><td>".__("LDAP Server URI:")."</td><td>".$ldapdb->{ldap_server}."</td></tr>";

        # summary text 
        $sum .= "<tr><td>".__("Kerberos Container DN:")."</td><td>".$ldapdb->{ldap_kerberos_container_dn}."</td></tr>";

        # summary text 
        $sum .= "<tr><td>".__("KDC bind DN:")."</td><td>".$ldapdb->{ldap_kdc_dn}."</td></tr>";

        # summary text 
        $sum .= "<tr><td>".__("Kadmin bind DN:")."</td><td>".$ldapdb->{ldap_kadmind_dn}."</td></tr>";

    }        
    
    $sum .= "</table>";

    return [
            $sum
           ];
}

##
 # Create an overview table with all configured cards
 # @return table items
 #
BEGIN { $TYPEINFO{Overview} = ["function", [ "list", "string" ] ]; }
sub Overview {
    # TODO FIXME: your code here...
    return [];
}

##
 # Return packages needed to be installed and removed during
 # Autoinstallation to insure module has all needed software
 # installed.
 # @return map with 2 lists.
 #
BEGIN { $TYPEINFO{AutoPackages} = ["function", ["map", "string", ["list", "string"]]]; }
sub AutoPackages {
    # TODO FIXME: your code here...
    my %ret = (
	"install" => (),
	"remove" => (),
    );
    return \%ret;
}

sub decodeTime
{
    my $class = shift;
    my $in = shift;

    my $out = "";

    if($in =~ /(\d*)\s*(\d\d):(\d\d):(\d\d)/)
    {
        if(defined $1 && $1 ne "")
        {
            $out .= "$1d ";
        }
        if(defined $2 && $2 ne "")
        {
            $out .= sprintf("%dh ", $2);
        }
        else
        {
            $out .= "0h ";
        }
        if(defined $3 && $3 ne "")
        {
            $out .= sprintf("%dm ", $3);
        }
        else
        {
            $out .= "0m ";
        }
        if(defined $4 && $4 ne "")
        {
            $out .= sprintf("%ds", $4);
        }
        else
        {
            $out .= "0s";
        }
    }
    else
    {
        y2error("Cannot convert time: $in");
        $out = "1h 0m 0s";
    }
    return $out;
}

BEGIN { $TYPEINFO{decodeDateTime} = ["function", ["list", "string"], "string"]; }
sub decodeDateTime
{
    my $class = shift;
    my $datetime = shift;

    my $date = "";
    my $time = "";
    # convert the datetime format   "yyyymmddhhmmss" => "yyy-mm-dd", "hh:mm:ss"
    if($datetime =~ /^\s*(\d\d\d\d)\.?(\d\d)\.?(\d\d)\.?(\d\d)\.?(\d\d)\.?(\d\d)\s*/)
    {
        $date = sprintf("%04d-%02d-%02d",$1, $2, $3);
        $time = sprintf("%02d:%02d:%02d",$4, $5, $6);
    }
    return ["$date","$time"];
}

BEGIN { $TYPEINFO{encodeDateTime} = ["function", "string", "string", "string"]; }
sub encodeDateTime
{
    my $class = shift;
    my $date  = shift || undef;
    my $time  = shift || undef;
    
    my $datetime = "";
    
    if(!defined $date || !defined $time)
    {
        return "20070101000000";
    }
        
    if($date =~ /^\s*(\d\d\d\d)-(\d\d)-(\d\d)\s*$/)
    {
        $datetime .= sprintf("%04d%02d%02d",$1, $2, $3);
    }
    else
    {
        $datetime = "20070101000000";
    }
    
    if($time =~ /^\s*(\d\d):(\d\d):(\d\d)\s*$/)
    {
        $datetime .= sprintf("%02d%02d%02d",$1, $2, $3);
    }
    else
    {
        $datetime = "20070101000000";
    }
    return $datetime;
}



sub encodeTime
{
    my $class = shift;
    my $in = shift;
    
    my $time = "";
    # convert the time format   "1d 2h 0m 0s" => "1 02:00:00"
    if($in =~ /((\d+)d\s)*(\d+)h\s?(\d+)m\s?(\d+)s\s*/)
    {
        if(defined $2 && $2 ne "")
        {
            $time .= "$2 ";
        }
        if(defined $3 && $3 ne "")
        {
            $time .= sprintf("%02d:", $3);
        }
        else
        {
            $time .= "00:";
        }
        if(defined $4 && $4 ne "")
        {
            $time .= sprintf("%02d:", $4);
        }
        else
        {
            $time .= "00:";
        }
        if(defined $5 && $5 ne "")
        {
            $time .= sprintf("%02d", $5);
        }
        else
        {
            $time .= "00";
        }
    }
    else
    {
        $time = "01:00:00";
    }
    return $time;   
}



sub toKdb5UtilTime
{
    my $class = shift;
    my $time = shift;
    
    my $new = "";
    
    if($time =~ /(\d*)\s*(\d\d):(\d\d):(\d\d)/)
    {
        if(defined $1 && $1 ne "")
        {
            $new .= ($1+1-1)."days ";
        }
        if(defined $2 && $2 ne "")
        {
            $new .= ($2+1-1)."hours ";
        }
        if(defined $3 && $3 ne "")
        {
            $new .= ($3+1-1)."minutes ";
        }
        if(defined $4 && $4 ne "")
        {
            $new .= ($4+1-1)."seconds ";
        }
    }
    else
    {
        y2error("Cannot convert time string: $time");
        $new = "1hours 0minutes 0seconds";
    }
    return $new;
}


sub num2flags
{
    my $class = shift;
    my $flags = shift;
    my $out = "";
    
    if( ($flags & 0x00000001) != 0)
    {
        $out .= "-allow_postdated ";
    }
    else
    {
        $out .= "+allow_postdated ";
    }
    
    if ( ($flags & 0x00000002) != 0)
    {
        $out .= "-allow_forwardable ";
    }
    else
    {
        $out .= "+allow_forwardable ";
    }

    if ( ($flags & 0x00000008) != 0)
    {
        $out .= "-allow_renewable ";
    }
    else
    {
        $out .= "+allow_renewable ";
    }

    if ( ($flags & 0x00000010) != 0)
    {
        $out .= "-allow_proxiable ";
    }
    else
    {
        $out .= "+allow_proxiable ";
    }

    if ( ($flags & 0x00000020) != 0)
    {
        $out .= "-allow_dup_skey ";
    }
    else
    {
        $out .= "+allow_dup_skey ";
    }

    if ( ($flags & 0x00000080) != 0)
    {
        $out .= "+requires_preauth ";
    }
    else
    {
        $out .= "-requires_preauth ";
    }

    if ( ($flags & 0x00000100) != 0)
    {
        $out .= "+requires_hwauth ";
    }
    else
    {
        $out .= "-requires_hwauth ";
    }

    if ( ($flags & 0x00001000) != 0)
    {
        $out .= "-allow_svr ";
    }
    else
    {
        $out .= "+allow_svr ";
    }


    if ( ($flags & 0x00000004) != 0)
    {
        $out .= "-allow_tgs_req ";
    }
    else
    {
        $out .= "+allow_tgs_req ";
    }

    if ( ($flags & 0x00000040) != 0)
    {
        $out .= "-allow_tix ";
    }
    else
    {
        $out .= "+allow_tix ";
    }

    if ( ($flags & 0x00000200) != 0)
    {
        $out .= "+needchange ";
    }
    else
    {
        $out .= "-needchange ";
    }

    if ( ($flags & 0x00002000) != 0)
    {
        $out .= "+password_changing_service ";
    }
    else
    {
        $out .= "-password_changing_service ";
    }
    return $out;
}


1;
# EOF

