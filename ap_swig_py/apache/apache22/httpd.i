/* vim: set sw=4 expandtab : */

%module(package="apache.apache22") httpd

%{
#include "apr_strings.h"
#include "httpd.h"
#include "http_protocol.h"
#include "http_core.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define APR_RING_ENTRY(elem) struct { struct elem *next; struct elem *prev; }
#define __attribute__(value)

%import "../_httpd.i"

%include "httpd.h"
