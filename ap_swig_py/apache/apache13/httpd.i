/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache13") httpd

%{
#include "httpd.h"
#include "http_protocol.h"
#include "http_core.h"
#include "ap_alloc.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_VAR_EXPORT
#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type
#define __attribute__(value)

%import "../_httpd.i"

%include "httpd.h"
