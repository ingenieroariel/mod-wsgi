/* vim: set sw=4 expandtab : */

%module(package="apache.apache22") http_main

%{
#include "httpd.h"
#include "http_main.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE_DATA
#define APR_DECLARE_OPTIONAL_FN(ret, name, args)

%include "http_main.h"
