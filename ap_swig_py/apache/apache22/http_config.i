/* vim: set sw=4 expandtab : */

%module(package="apache.apache22") http_config

%{
#include "httpd.h"
#include "http_config.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE(type) type
#define AP_DECLARE_NONSTD(type) type
#define AP_DECLARE_DATA
#define AP_DECLARE_HOOK(ret, name, args)

/* Follow may not work with some compilers. */
%ignore AP_HAVE_DESIGNATED_INITIALIZER;
#define AP_HAVE_DESIGNATED_INITIALIZER 1

%include "http_config.h"
