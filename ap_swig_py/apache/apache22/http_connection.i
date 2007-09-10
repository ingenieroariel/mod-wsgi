/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache22") http_connection

%{
#include "httpd.h"
#include "http_connection.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE(type) type
#define AP_DECLARE_DATA
#define AP_DECLARE_HOOK(ret, name, args)

int AP_BUCKET_IS_EOC(apr_bucket *e) {
    return AP_BUCKET_IS_EOC(e);
}

%include "http_connection.h"
