/* vim: set sw=4 expandtab : */

%feature("immutable","0") request_rec::ap_auth_type;
%feature("immutable","0") request_rec::args;
%feature("immutable","0") request_rec::assbackwards;
%feature("immutable","0") request_rec::content_encoding;
%feature("immutable","0") request_rec::content_length;
%feature("immutable","0") request_rec::content_type;
%feature("immutable","0") request_rec::filename;
%feature("immutable","0") request_rec::finfo;
%feature("immutable","0") request_rec::handler;
%feature("immutable","0") request_rec::no_cache;
%feature("immutable","0") request_rec::no_local_copy;
%feature("immutable","0") request_rec::handler;
%feature("immutable","0") request_rec::path_info;
%feature("immutable","0") request_rec::proxyreq;
%feature("immutable","0") request_rec::status;
%feature("immutable","0") request_rec::status_line;
%feature("immutable","0") request_rec::uri;
%feature("immutable","0") request_rec::user;

%import "http_protocol.i"
%import "http_core.i"
%import "util_script.i"
%import "apr_tables.i"

%extend conn_rec {
    conn_rec(PyObject *obj) {
        return (conn_rec *) PyCObject_AsVoidPtr(obj);
    }
}

%extend server_rec {
    server_rec(PyObject *obj) {
        return (server_rec *) PyCObject_AsVoidPtr(obj);
    }
}

%warnfilter(451) request_rec;

%extend request_rec {

    request_rec(PyObject *obj) {
        return (request_rec *) PyCObject_AsVoidPtr(obj);
    }
}

%{

void request_rec_ap_auth_type_set(request_rec *self, const char *str) {
    self->ap_auth_type = apr_pstrdup(self->pool, str);
}

void request_rec_ap_args_set(request_rec *self, const char *str) {
    self->args = apr_pstrdup(self->pool, str);
}

void request_rec_content_encoding_set(request_rec *self, const char *str) {
    self->content_encoding = (const char *)apr_pstrdup(self->pool, str);
}

void request_rec_content_length_set(request_rec *self, apr_off_t length) {
    ap_set_content_length(self, length);
}

void request_rec_content_type_set(request_rec *self, const char *str) {
    ap_set_content_type(self, str);
}

void request_rec_filename_set(request_rec *self, const char *str) {
    self->filename = apr_pstrdup(self->pool, str);
}

void request_rec_handler_set(request_rec *self, const char *str) {
    self->handler = (const char *)apr_pstrdup(self->pool, str);
}

void request_rec_path_info_set(request_rec *self, const char *str) {
    self->path_info = apr_pstrdup(self->pool, str);
}

void request_rec_status_line_set(request_rec *self, const char *str) {
    self->status_line = apr_pstrdup(self->pool, str);
}

void request_rec_uri_set(request_rec *self, const char *str) {
    self->uri = apr_pstrdup(self->pool, str);
}

void request_rec_user_set(request_rec *self, const char *str) {
    self->user = apr_pstrdup(self->pool, str);
}

%}
