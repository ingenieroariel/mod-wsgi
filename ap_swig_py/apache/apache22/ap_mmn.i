/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache22") ap_mmn

%{
#include "ap_mmn.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_DECLARE(type) type
#define AP_DECLARE_HOOK(ret, name, args)

int AP_MODULE_MAGIC_AT_LEAST(int major, int minor) {
  return AP_MODULE_MAGIC_AT_LEAST(major, minor);
}

%include "ap_mmn.h"
