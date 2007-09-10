/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache20") http_log

%{
#include "httpd.h"
#include "http_log.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

%import "apr_errno.i"

#define AP_DECLARE(type) type
#define AP_DECLARE_DATA
#define AP_DECLARE_HOOK(ret, name, args)
#define __attribute__(value)

int ap_piped_log_read_fd(piped_log *pl) {
    return ap_piped_log_read_fd(pl);
}

int ap_piped_log_write_fd(piped_log *pl) {
    return ap_piped_log_write_fd(pl);
}

%include "http_log.h"
