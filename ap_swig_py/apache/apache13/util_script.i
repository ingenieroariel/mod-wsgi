/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache13") util_script

%{
#include "httpd.h"
#include "util_script.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type

%include "util_script.h"
