/* vim: set sw=4 expandtab : */

%module(package="apache.apache13") http_request

%{
#include "httpd.h"
#include "http_request.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type

%include "http_request.h"
