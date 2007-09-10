/* vim: set sw=4 expandtab : */

%module(package="mod_grumpy.bindings.apache20") apr_errno

%{
#include "apr_errno.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

#define APR_DECLARE(type) type

apr_status_t APR_FROM_OS_ERROR(int e) {
    return APR_FROM_OS_ERROR(e);
}

int APR_TO_OS_ERROR(apr_status_t e) {
    return APR_TO_OS_ERROR(e);
}

apr_status_t apr_get_netos_error() {
    return apr_get_netos_error();
}

void apr_set_netos_error(int e) {
    apr_set_netos_error(e);
}

int APR_STATUS_IS_EACCES(apr_status_t s) {
    return APR_STATUS_IS_EACCES(s);
}

int APR_STATUS_IS_EEXIST(apr_status_t s) {
    return APR_STATUS_IS_EEXIST(s);
}

int APR_STATUS_IS_ENAMETOOLONG(apr_status_t s) {
    return APR_STATUS_IS_ENAMETOOLONG(s);
}

int APR_STATUS_IS_ENOENT(apr_status_t s) {
    return APR_STATUS_IS_ENOENT(s);
}

int APR_STATUS_IS_ENOTDIR(apr_status_t s) {
    return APR_STATUS_IS_ENOTDIR(s);
}

int APR_STATUS_IS_ENOSPC(apr_status_t s) {
    return APR_STATUS_IS_ENOSPC(s);
}

int APR_STATUS_IS_ENOMEM(apr_status_t s) {
    return APR_STATUS_IS_ENOMEM(s);
}

int APR_STATUS_IS_EMFILE(apr_status_t s) {
    return APR_STATUS_IS_EMFILE(s);
}

int APR_STATUS_IS_ENFILE(apr_status_t s) {
    return APR_STATUS_IS_ENFILE(s);
}

int APR_STATUS_IS_EBADF(apr_status_t s) {
    return APR_STATUS_IS_EBADF(s);
}

int APR_STATUS_IS_EINVAL(apr_status_t s) {
    return APR_STATUS_IS_EINVAL(s);
}

int APR_STATUS_IS_ESPIPE(apr_status_t s) {
    return APR_STATUS_IS_ESPIPE(s);
}

int APR_STATUS_IS_EAGAIN(apr_status_t s) {
    return APR_STATUS_IS_EAGAIN(s);
}

int APR_STATUS_IS_EINTR(apr_status_t s) {
    return APR_STATUS_IS_EINTR(s);
}

int APR_STATUS_IS_ENOTSOCK(apr_status_t s) {
    return APR_STATUS_IS_ENOTSOCK(s);
}

int APR_STATUS_IS_ENOTSOCK(apr_status_t s) {
    return APR_STATUS_IS_ENOTSOCK(s);
}

int APR_STATUS_IS_ECONNREFUSED(apr_status_t s) {
    return APR_STATUS_IS_ECONNREFUSED(s);
}

int APR_STATUS_IS_EINPROGRESS(apr_status_t s) {
    return APR_STATUS_IS_EINPROGRESS(s);
}

int APR_STATUS_IS_ECONNABORTED(apr_status_t s) {
    return APR_STATUS_IS_ECONNABORTED(s);
}

int APR_STATUS_IS_ECONNRESET(apr_status_t s) {
    return APR_STATUS_IS_ECONNRESET(s);
}

int APR_STATUS_IS_ETIMEDOUT(apr_status_t s) {
    return APR_STATUS_IS_ETIMEDOUT(s);
}

int APR_STATUS_IS_TIMEUP(apr_status_t s) {
    return APR_STATUS_IS_TIMEUP(s);
}

int APR_STATUS_IS_EHOSTUNREACH(apr_status_t s) {
    return APR_STATUS_IS_EHOSTUNREACH(s);
}

int APR_STATUS_IS_ENETUNREACH(apr_status_t s) {
    return APR_STATUS_IS_ENETUNREACH(s);
}

int APR_STATUS_IS_EFTYPE(apr_status_t s) {
    return APR_STATUS_IS_EFTYPE(s);
}

int APR_STATUS_IS_EPIPE(apr_status_t s) {
    return APR_STATUS_IS_EPIPE(s);
}

int APR_STATUS_IS_EXDEV(apr_status_t s) {
    return APR_STATUS_IS_EXDEV(s);
}

int APR_STATUS_IS_ENOTEMPTY(apr_status_t s) {
    return APR_STATUS_IS_ENOTEMPTY(s);
}

%include "apr_errno.h"
