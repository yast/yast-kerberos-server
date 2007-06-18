#! /usr/bin/perl -w

BEGIN {
    #push @INC, '/usr/share/YaST2/modules/';
    push @INC, '../src/';
}

use strict;
use Data::Dumper;
use YaST::YCP qw(Boolean);
use ycp;
use KerberosServer;
YaST::YCP::Import ("SCR");


y2milestone("execute kadmin SCR");

my $kadmin_args  = { "princ"   => "admin/admin", 
                     "adminpw" => "system",
                   };
my $ret = SCR->Execute(".kadmin.init", $kadmin_args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}

###################################################################

my $args = {
            "cmd_args" => ["ugansert"],
            "cmd_input" => ["system", "system"]
           };
$ret = SCR->Execute(".kadmin.add_principal", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {
         "cmd_args" => ["+needchange", "ugansert"],
        };
$ret = SCR->Execute(".kadmin.modify_principal", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {
         "cmd_args" => ["ugansert"],
        };
$ret = SCR->Execute(".kadmin.get_principal", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {
            "cmd_args" => ["ugansert"],
            "cmd_input" => ["szstem", "szstem"]
           };
$ret = SCR->Execute(".kadmin.change_password", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {
            "cmd_args" => ["ugansert"],
            "cmd_input" => ["yes"]
           };
$ret = SCR->Execute(".kadmin.delete_principal", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);


###################################################################

$args = {};
$ret = SCR->Execute(".kadmin.list_principals", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}

###################################################################

$args = {
         "cmd_args" => ["-maxlife", "3 month", "defaultpol"],
        };
$ret = SCR->Execute(".kadmin.add_policy", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);


###################################################################

$args = {
         "cmd_args" => ["-minlength", "6", "defaultpol"],
        };
$ret = SCR->Execute(".kadmin.modify_policy", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {};
$ret = SCR->Execute(".kadmin.list_policies", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {
         "cmd_args" => ["defaultpol"],
        };
$ret = SCR->Execute(".kadmin.get_policy", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);


###################################################################

$args = {
         "cmd_args" => ["-force", "defaultpol"],
        };
$ret = SCR->Execute(".kadmin.delete_policy", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {
         "cmd_args" => ["-k", "./dummy.keytab", "host/tait.suse.de"],
        };
$ret = SCR->Execute(".kadmin.ktadd", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);

###################################################################

$args = {
         "cmd_args" => ["-k", "./dummy.keytab", "host/tait.suse.de", "all"],
        };
$ret = SCR->Execute(".kadmin.ktremove", $args);
if(!defined $ret)
{
    print "ERROR: ".Data::Dumper->Dump([SCR->Error(".kadmin")])."\n";
    exit 1;
}
print "Return value:".Data::Dumper->Dump([$ret]);



#print Data::Dumper->Dump([$ret])."\n";
#print "$ret\n";



