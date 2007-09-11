/* vim: set sw=4 expandtab : */

%module(package="apache.apache13") http_log

%{
#include "httpd.h"
#include "http_log.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

%import "apr_errno.i"

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type
#define __attribute__(value)

int ap_piped_log_read_fd(piped_log *pl) {
    return ap_piped_log_read_fd(pl);
}

int ap_piped_log_write_fd(piped_log *pl) {
    return ap_piped_log_write_fd(pl);
}

%include "http_log.h"

%pythoncode %{

def ap_log_error(file, line, level, status, s, data):
    return _http_log.ap_log_error(file, line, level, s, data)

def ap_log_cerror(file, line, level, status, c, data):
    return _http_log.ap_log_error(file, line, level, None, data)

def ap_log_rerror(file, line, level, status, r, data):
    return _http_log.ap_log_rerror(file, line, level, r, data)

%}
