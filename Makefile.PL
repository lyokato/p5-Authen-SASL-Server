use inc::Module::Install;
name 'Authen-SASL-Server';
all_from 'lib/Authen/SASL/Server.pm';
build_requires 'Test::More';
build_requires 'Authen::SASL';
requires 'Class::Accessor'       => '0.31';
requires 'Class::ErrorHandler'   => '0.01';
requires 'Class::Data::Accessor' => '0.04001';
requires 'Digest::MD5'           => '2.36';
requires 'UNIVERSAL::require'    => '0.01';
auto_include;
WriteAll;
