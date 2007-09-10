/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache13") http_protocol

%{
#include "httpd.h"
#include "http_protocol.h"
#include "ap_compat.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type
#define CORE_EXPORT(type) type
#define __attribute__(value)

%import "../_http_protocol.i"

%include "http_protocol.h"
