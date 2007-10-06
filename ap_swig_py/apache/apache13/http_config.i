/* vim: set sw=4 expandtab : */

%module(package="apache.apache13") http_config

%{
#include "httpd.h"
#include "http_config.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type

%include "http_config.h"