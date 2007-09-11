/* vim: set sw=4 expandtab : */

%module(package="apache.apache20") ap_mmn

%{
#include "httpd.h"
#include "ap_mpm.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE(type) type

%include "ap_mpm.h"

%import "apr_errno.i"
%import "cpointer.i"

%pointer_functions(int, int_p)

%pythoncode %{

def ap_mpm_query(query_code):
    value = new_int_p()
    try:
        result = _ap_mpm.ap_mpm_query(query_code, value)
        if result != apr_errno.APR_SUCCESS:
            raise NotImplementedError
        result = int_p_value(value)
        return result
    finally:
        delete_int_p(value)

%}
