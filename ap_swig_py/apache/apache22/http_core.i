/* vim: set sw=4 expandtab : */

%module(package="apache.apache22") http_core

%{
#include "http_core.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE(type) type
#define AP_DECLARE_NONSTD(type) type
#define AP_DECLARE_DATA
#define AP_DECLARE_HOOK(ret, name, args)
#define APR_DECLARE_OPTIONAL_FN(ret, name, args)

%include "http_core.h"
