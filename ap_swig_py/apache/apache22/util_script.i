/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache22") util_script

%{
#include "httpd.h"
#include "util_script.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE(type) type
#define AP_DECLARE_NONSTD(type) type

%include "util_script.h"
