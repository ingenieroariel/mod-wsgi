/* vim: set sw=4 expandtab : */

%module(package="apache.apache13") ap_mpm

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define AP_MPMQ_NOT_SUPPORTED         0
#define AP_MPMQ_STATIC                1
#define AP_MPMQ_DYNAMIC               2

#define AP_MPMQ_STARTING              0
#define AP_MPMQ_RUNNING               1
#define AP_MPMQ_STOPPING              2

#define AP_MPMQ_MAX_DAEMON_USED       1
#define AP_MPMQ_IS_THREADED           2
#define AP_MPMQ_IS_FORKED             3
#define AP_MPMQ_HARD_LIMIT_DAEMONS    4
#define AP_MPMQ_HARD_LIMIT_THREADS    5
#define AP_MPMQ_MAX_THREADS           6
#define AP_MPMQ_MIN_SPARE_DAEMONS     7
#define AP_MPMQ_MIN_SPARE_THREADS     8
#define AP_MPMQ_MAX_SPARE_DAEMONS     9
#define AP_MPMQ_MAX_SPARE_THREADS    10
#define AP_MPMQ_MAX_REQUESTS_DAEMON  11
#define AP_MPMQ_MAX_DAEMONS          12
#define AP_MPMQ_MPM_STATE            13
#define AP_MPMQ_IS_ASYNC             14

%pythoncode %{

def ap_mpm_query(query_code):
    if query_code == AP_MPMQ_IS_THREADED:
        return AP_MPMQ_NOT_SUPPORTED
    elif query_code == AP_MPMQ_IS_FORKED:
        return AP_MPMQ_DYNAMIC
    raise NotImplementedError()

%}
