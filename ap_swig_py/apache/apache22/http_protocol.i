/* vim: set sw=4 expandtab : */

%module(package="apache.apache22") http_protocol

%{
#include "http_protocol.h"
#include "ap_compat.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE(type) type
#define AP_DECLARE_NONSTD(type) type
#define AP_DECLARE_DATA
#define AP_DECLARE_HOOK(ret, name, args)
#define AP_CORE_DECLARE(type) type
#define __attribute__(value)

void ap_send_http_header(request_rec *r);

%import "../_http_protocol.i"

%include "http_protocol.h"
