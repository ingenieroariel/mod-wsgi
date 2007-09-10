/* vim: set sw=4 expandtab : */

%ignore ap_rputs;
%ignore ap_rputc;

%exception ap_rflush {
    Py_BEGIN_ALLOW_THREADS
    $action
    Py_END_ALLOW_THREADS
}

%exception ap_rwrite {
    Py_BEGIN_ALLOW_THREADS
    $action
    Py_END_ALLOW_THREADS
}

/* How can this be made more precise so that it refers only to ap_rwrite(). */
%apply (char *STRING, int LENGTH) { (const void *buf, int nbyte) };
