/* vim: set sw=4 expandtab : */

%module(package="apache.apache22") mod_auth

%{
#include "mod_auth.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%include "mod_auth.h"
