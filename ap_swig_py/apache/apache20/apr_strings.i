/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache20") apr_strings

%{
#include "apr_strings.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define APR_DECLARE(type) type
#define APR_DECLARE_NONSTD(type) type
#define __attribute__(value)

%include "apr_strings.h"
