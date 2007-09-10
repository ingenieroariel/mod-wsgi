/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache13") http_vhost

%{
#include "httpd.h"
#include "http_config.h"
#include "http_vhost.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type

%include "http_vhost.h"
