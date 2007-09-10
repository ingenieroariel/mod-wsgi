/* vim: set sw=4 expandtab : */

/*
 * Apache 1.3 didn't have a separate 'apr_errno.h' so need to
 * fake up minimal module with what equivalent functions existed
 * and which were usable.
 */

%module(package="mod_grumpy.bindings.apache13") apr_errno

%nodefaultctor;
%nodefaultdtor;

%immutable;

#define APR_SUCCESS 0
