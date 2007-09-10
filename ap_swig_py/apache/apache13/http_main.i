/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache13") http_main

%{
#include "httpd.h"
#include "http_main.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type

%include "http_main.h"
