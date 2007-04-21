/* vim: set sw=4 expandtab : */

/*
 * Copyright 2007 GRAHAM DUMPLETON
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"

#if !defined(AP_SERVER_MAJORVERSION_NUMBER)
#if AP_MODULE_MAGIC_AT_LEAST(20010224,0)
#define AP_SERVER_MAJORVERSION_NUMBER 2
#else
#define AP_SERVER_MAJORVERSION_NUMBER 1
#endif
#endif

#if !defined(AP_SERVER_BASEVERSION)
#define AP_SERVER_BASEVERSION SERVER_BASEVERSION
#endif

#if AP_SERVER_MAJORVERSION_NUMBER < 2
typedef int apr_status_t;
#define APR_SUCCESS 0
typedef pool apr_pool_t;
typedef unsigned int apr_port_t;
#include "ap_alloc.h"
#define apr_table_get ap_table_get
#define apr_table_set ap_table_set
#define apr_table_setn ap_table_setn
#define apr_table_elts ap_table_elts
#define apr_array_make ap_make_array
#define apr_array_push ap_push_array
#define apr_array_cat ap_array_cat
#define apr_array_append ap_append_arrays
typedef array_header apr_array_header_t;
typedef table_entry apr_table_entry_t;
typedef int apr_size_t;
#define apr_psprintf ap_psprintf
#define apr_pstrndup ap_pstrndup
#define apr_pstrdup ap_pstrdup
#define apr_pstrcat ap_pstrcat
#define apr_pcalloc ap_pcalloc
typedef time_t apr_time_t;
#define CORE_PRIVATE 1
#include "http_config.h"
#undef CORE_PRIVATE
#else
#include "ap_mpm.h"
#include "ap_compat.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "http_config.h"
#include "ap_listen.h"
#endif

#include "ap_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "util_md5.h"

#if !AP_MODULE_MAGIC_AT_LEAST(20050127,0)
/* Debian backported ap_regex_t to Apache 2.0 and
 * thus made official version checking break. */
#ifndef AP_REG_EXTENDED
typedef regex_t ap_regex_t;
typedef regmatch_t ap_regmatch_t;
#define AP_REG_EXTENDED REG_EXTENDED
#endif
#endif

#if !defined(WIN32)
#if AP_SERVER_MAJORVERSION_NUMBER >= 2
#if !AP_MODULE_MAGIC_AT_LEAST(20051115,0)
static void ap_close_listeners(void)
{
    ap_listen_rec *lr;

    for (lr = ap_listeners; lr; lr = lr->next) {
        apr_socket_close(lr->sd);
        lr->active = 0;
    }
}
#endif
#endif
#endif

#include "Python.h"
#include "compile.h"
#include "node.h"

#if !defined(PY_VERSION_HEX) || PY_VERSION_HEX <= 0x02030000
#error Sorry, mod_wsgi requires at least Python 2.3.0.
#endif

#if !defined(WITH_THREAD)
#error Sorry, mod_wsgi requires that Python supporting thread.
#endif

/* Version information. */

#define MOD_WSGI_MAJORVERSION_NUMBER 1
#define MOD_WSGI_MINORVERSION_NUMBER 0

#if AP_SERVER_MAJORVERSION_NUMBER < 2
module MODULE_VAR_EXPORT wsgi_module;
#else
module AP_MODULE_DECLARE_DATA wsgi_module;
#endif

/* Configuration objects. */

typedef struct {
    const char *location;
    const char *application;
    ap_regex_t *regexp;
} WSGIAliasEntry;

typedef struct {
    apr_pool_t *pool;

    apr_array_header_t *alias_list;

    apr_array_header_t *daemon_list;
    const char *socket_prefix;

    int python_optimize;
    int restrict_stdin;
    int restrict_stdout;
    int restrict_signal;

    const char *process_name;
    const char *application_group;
    const char *callable_object;

    int pass_authorization;
    int script_reloading;
    int reload_mechanism;
    int output_buffering;
} WSGIServerConfig;

static WSGIServerConfig *wsgi_server_config = NULL;

static WSGIServerConfig *newWSGIServerConfig(apr_pool_t *p)
{
    WSGIServerConfig *object = NULL;

    object = (WSGIServerConfig *)apr_pcalloc(p, sizeof(WSGIServerConfig));

    object->pool = p;

    object->alias_list = NULL;

    object->daemon_list = NULL;
    object->socket_prefix = NULL;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    object->socket_prefix = DEFAULT_REL_RUNTIMEDIR "/wsgisock";
    object->socket_prefix = apr_psprintf(p, "%s.%d", object->socket_prefix,
                                         getpid());
    object->socket_prefix = ap_server_root_relative(p, object->socket_prefix);
#endif

    object->python_optimize = -1;
    object->restrict_stdin = -1;
    object->restrict_stdout = -1;
    object->restrict_signal = -1;

    object->process_name = NULL;
    object->application_group = NULL;
    object->callable_object = NULL;

    object->pass_authorization = -1;
    object->script_reloading = -1;
    object->reload_mechanism = -1;
    object->output_buffering = -1;

    return object;
}

static void *wsgi_create_server_config(apr_pool_t *p, server_rec *s)
{
    WSGIServerConfig *config = NULL;

    config = newWSGIServerConfig(p);

    return config;
}

static void *wsgi_merge_server_config(apr_pool_t *p, void *base_conf,
                                      void *new_conf)
{
    WSGIServerConfig *config = NULL;
    WSGIServerConfig *parent = NULL;
    WSGIServerConfig *child = NULL;

    config = newWSGIServerConfig(p);

    parent = (WSGIServerConfig *)base_conf;
    child = (WSGIServerConfig *)new_conf;

    if (child->alias_list && parent->alias_list) {
        config->alias_list = apr_array_append(p, child->alias_list,
                                              parent->alias_list);
    }
    else if (child->alias_list) {
        config->alias_list = apr_array_make(p, 20, sizeof(WSGIAliasEntry));
        apr_array_cat(config->alias_list, child->alias_list);
    }
    else if (parent->alias_list) {
        config->alias_list = apr_array_make(p, 20, sizeof(WSGIAliasEntry));
        apr_array_cat(config->alias_list, parent->alias_list);
    }

    if (child->process_name)
        config->process_name = child->process_name;
    else
        config->process_name = parent->process_name;

    if (child->application_group)
        config->application_group = child->application_group;
    else
        config->application_group = parent->application_group;

    if (child->callable_object)
        config->callable_object = child->callable_object;
    else
        config->callable_object = parent->callable_object;

    if (child->pass_authorization != -1)
        config->pass_authorization = child->pass_authorization;
    else
        config->pass_authorization = parent->pass_authorization;

    if (child->script_reloading != -1)
        config->script_reloading = child->script_reloading;
    else
        config->script_reloading = parent->script_reloading;

    if (child->reload_mechanism != -1)
        config->reload_mechanism = child->reload_mechanism;
    else
        config->reload_mechanism = parent->reload_mechanism;

    if (child->output_buffering != -1)
        config->output_buffering = child->output_buffering;
    else
        config->output_buffering = parent->output_buffering;

    return config;
}

typedef struct {
    apr_pool_t *pool;

    const char *process_name;
    const char *application_group;
    const char *callable_object;

    int pass_authorization;
    int script_reloading;
    int reload_mechanism;
    int output_buffering;
} WSGIDirectoryConfig;

static WSGIDirectoryConfig *newWSGIDirectoryConfig(apr_pool_t *p)
{
    WSGIDirectoryConfig *object = NULL;

    object = (WSGIDirectoryConfig *)apr_pcalloc(p, sizeof(WSGIDirectoryConfig));

    object->pool = p;

    object->process_name = NULL;
    object->application_group = NULL;
    object->callable_object = NULL;

    object->pass_authorization = -1;
    object->script_reloading = -1;
    object->reload_mechanism = -1;
    object->output_buffering = -1;

    return object;
}

static void *wsgi_create_dir_config(apr_pool_t *p, char *dir)
{
    WSGIDirectoryConfig *config = NULL;

    config = newWSGIDirectoryConfig(p);

    return config;
}

static void *wsgi_merge_dir_config(apr_pool_t *p, void *base_conf,
                                   void *new_conf)
{
    WSGIDirectoryConfig *config = NULL;
    WSGIDirectoryConfig *parent = NULL;
    WSGIDirectoryConfig *child = NULL;

    config = newWSGIDirectoryConfig(p);

    parent = (WSGIDirectoryConfig *)base_conf;
    child = (WSGIDirectoryConfig *)new_conf;

    if (child->process_name)
        config->process_name = child->process_name;
    else
        config->process_name = parent->process_name;

    if (child->application_group)
        config->application_group = child->application_group;
    else
        config->application_group = parent->application_group;

    if (child->callable_object)
        config->callable_object = child->callable_object;
    else
        config->callable_object = parent->callable_object;

    if (child->pass_authorization != -1)
        config->pass_authorization = child->pass_authorization;
    else
        config->pass_authorization = parent->pass_authorization;

    if (child->script_reloading != -1)
        config->script_reloading = child->script_reloading;
    else
        config->script_reloading = parent->script_reloading;

    if (child->reload_mechanism != -1)
        config->reload_mechanism = child->reload_mechanism;
    else
        config->reload_mechanism = parent->reload_mechanism;

    if (child->output_buffering != -1)
        config->output_buffering = child->output_buffering;
    else
        config->output_buffering = parent->output_buffering;

    return config;
}

typedef struct {
    apr_pool_t *pool;

    const char *process_name;
    const char *application_group;
    const char *callable_object;

    int pass_authorization;
    int script_reloading;
    int reload_mechanism;
    int output_buffering;
} WSGIRequestConfig;

static const char *wsgi_script_name(request_rec *r)
{
    const char *script_name = NULL;
    int path_info_start = 0;

    if (!r->path_info || !*r->path_info) {
        script_name = r->uri;
    }
    else {
        path_info_start = ap_find_path_info(r->uri, r->path_info);

        script_name = apr_pstrndup(r->pool, r->uri, path_info_start);
    }

    if (*script_name) {
        while (*script_name && (*(script_name+1) == '/'))
            script_name++;
        script_name = apr_pstrdup(r->pool, script_name);
        ap_no2slash((char*)script_name);
    }

    return script_name;
}

static const char *wsgi_process_name(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    if (!s)
        return "";

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name) {
        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (strstr(name, "{ENV:") == name) {
            int len = 0;

            name = name + 5;
            len = strlen(name);

            if (len && name[len-1] == '}') {
                name = apr_pstrndup(r->pool, name, len-1);

                value = apr_table_get(r->notes, name);

                if (!value)
                    value = apr_table_get(r->subprocess_env, name);

                if (!value)
                    value = getenv(name);

                if (value)
                    return value;
            }
        }
    }

    return s;
}

static const char *wsgi_application_group(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    const char *h = NULL;
    apr_port_t p = 0;
    const char *n = NULL;

    if (!s) {
        h = r->server->server_hostname;
        p = ap_get_server_port(r);
        n = wsgi_script_name(r);

        if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
            return apr_psprintf(r->pool, "%s:%u|%s", h, p, n);
        else
            return apr_psprintf(r->pool, "%s|%s", h, n);
    }

    if (*s != '%')
        return s;

    name = s + 1;

    if (*name) {
        if (!strcmp(name, "{RESOURCE}")) {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);
            n = wsgi_script_name(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u|%s", h, p, n);
            else
                return apr_psprintf(r->pool, "%s|%s", h, n);
        }

        if (!strcmp(name, "{SERVER}")) {
            h = r->server->server_hostname;
            p = ap_get_server_port(r);

            if (p != DEFAULT_HTTP_PORT && p != DEFAULT_HTTPS_PORT)
                return apr_psprintf(r->pool, "%s:%u", h, p);
            else
                return h;
        }

        if (!strcmp(name, "{GLOBAL}"))
            return "";

        if (strstr(name, "{ENV:") == name) {
            int len = 0;

            name = name + 5;
            len = strlen(name);

            if (len && name[len-1] == '}') {
                name = apr_pstrndup(r->pool, name, len-1);

                value = apr_table_get(r->notes, name);

                if (!value)
                    value = apr_table_get(r->subprocess_env, name);

                if (!value)
                    value = getenv(name);

                if (value)
                    return value;
            }
        }
    }

    return s;
}

static const char *wsgi_callable_object(request_rec *r, const char *s)
{
    const char *name = NULL;
    const char *value = NULL;

    if (!s)
        return "application";

    if (*s != '%')
        return s;

    name = s + 1;

    if (!*name)
        return "application";

    if (strstr(name, "{ENV:") == name) {
        int len = 0;

        name = name + 5;
        len = strlen(name);

        if (len && name[len-1] == '}') {
            name = apr_pstrndup(r->pool, name, len-1);

            value = apr_table_get(r->notes, name);

            if (!value)
                value = apr_table_get(r->subprocess_env, name);

            if (!value)
                value = getenv(name);

            if (value)
                return value;
        }
    }

    return "application";
}

static WSGIRequestConfig *wsgi_create_req_config(apr_pool_t *p, request_rec *r)
{
    WSGIRequestConfig *config = NULL;
    WSGIServerConfig *sconfig = NULL;
    WSGIDirectoryConfig *dconfig = NULL;

    config = (WSGIRequestConfig *)apr_pcalloc(p, sizeof(WSGIRequestConfig));

    dconfig = ap_get_module_config(r->per_dir_config, &wsgi_module);
    sconfig = ap_get_module_config(r->server->module_config, &wsgi_module);

    config->pool = p;

    config->process_name = dconfig->process_name;

    if (!config->process_name)
        config->process_name = sconfig->process_name;

    config->process_name = wsgi_process_name(r, config->process_name);

    config->application_group = dconfig->application_group;

    if (!config->application_group)
        config->application_group = sconfig->application_group;

    config->application_group = wsgi_application_group(r,
                                    config->application_group);

    config->callable_object = dconfig->callable_object;

    if (!config->callable_object)
        config->callable_object = sconfig->callable_object;

    config->callable_object = wsgi_callable_object(r, config->callable_object);

    config->pass_authorization = dconfig->pass_authorization;

    if (config->pass_authorization < 0) {
        config->pass_authorization = sconfig->pass_authorization;
        if (config->pass_authorization < 0)
            config->pass_authorization = 0;
    }

    config->script_reloading = dconfig->script_reloading;

    if (config->script_reloading < 0) {
        config->script_reloading = sconfig->script_reloading;
        if (config->script_reloading < 0)
            config->script_reloading = 1;
    }

    config->reload_mechanism = dconfig->reload_mechanism;

    if (config->reload_mechanism < 0) {
        config->reload_mechanism = sconfig->reload_mechanism;
        if (config->reload_mechanism < 0)
            config->reload_mechanism = 0;
    }

    config->output_buffering = dconfig->output_buffering;

    if (config->output_buffering < 0) {
        config->output_buffering = sconfig->output_buffering;
        if (config->output_buffering < 0)
            config->output_buffering = 0;
    }

    return config;
}

/*
 * Class objects used by response handler.
 */

typedef struct {
        PyObject_HEAD
        request_rec *r;
        int level;
        char *s;
} LogObject;

static PyTypeObject Log_Type;

static LogObject *newLogObject(request_rec *r)
{
    LogObject *self;

    self = PyObject_New(LogObject, &Log_Type);
    if (self == NULL)
        return NULL;

    self->r = r;
    self->level = APLOG_NOERRNO|APLOG_ERR;
    self->s = NULL;

    return self;
}

static void Log_dealloc(LogObject *self)
{
    if (self->s) {
        if (self->r) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            ap_log_rerror(APLOG_MARK, self->level, self->r, "%s", self->s);
#else
            ap_log_rerror(APLOG_MARK, self->level, 0, self->r, "%s", self->s);
#endif
        }
        else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            ap_log_error(APLOG_MARK, self->level, 0, "%s", self->s);
#else
            ap_log_error(APLOG_MARK, self->level, 0, 0, "%s", self->s);
#endif
        }

        free(self->s);
    }

    PyObject_Del(self);
}

static PyObject *Log_flush(LogObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":flush"))
        return NULL;

    if (self->s) {
        if (self->r) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            ap_log_rerror(APLOG_MARK, self->level, self->r, "%s", self->s);
#else
            ap_log_rerror(APLOG_MARK, self->level, 0, self->r, "%s", self->s);
#endif
        }
        else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            ap_log_error(APLOG_MARK, self->level, 0, "%s", self->s);
#else
            ap_log_error(APLOG_MARK, self->level, 0, 0, "%s", self->s);
#endif
        }

        free(self->s);
        self->s = NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static void Log_output(LogObject *self, const char *msg)
{
    const char *p = NULL;
    const char *q = NULL;

    p = msg;

    q = strchr(p, '\n');

    while (q) {
        /* Output each complete line. */

        if (self->s) {
            /* Need to join with buffered value. */

            int m = 0;
            int n = 0;
            char *s = NULL;

            m = strlen(self->s);
            n = m+q-p+1;

            s = (char *)malloc(n);
            strncpy(s, self->s, m);
            strncpy(s+m, p, q-p);
            s[n-1] = '\0';

            if (self->r) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                ap_log_rerror(APLOG_MARK, self->level, self->r, "%s", s);
#else
                ap_log_rerror(APLOG_MARK, self->level, 0, self->r, "%s", s);
#endif
            }
            else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                ap_log_error(APLOG_MARK, self->level, 0, "%s", s);
#else
                ap_log_error(APLOG_MARK, self->level, 0, 0, "%s", s);
#endif
            }

            free(self->s);
            self->s = NULL;

            free(s);
        }
        else {
            int n = 0;
            char *s = NULL;

            n = q-p+1;

            s = (char *)malloc(n);
            strncpy(s, p, q-p);
            s[n-1] = '\0';

            if (self->r) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                ap_log_rerror(APLOG_MARK, self->level, self->r, "%s", s);
#else
                ap_log_rerror(APLOG_MARK, self->level, 0, self->r, "%s", s);
#endif
            }
            else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                ap_log_error(APLOG_MARK, self->level, 0, "%s", s);
#else
                ap_log_error(APLOG_MARK, self->level, 0, 0, "%s", s);
#endif
            }

            free(s);
        }

        p = q+1;
        q = strchr(p, '\n');
    }

    if (*p) {
        /* Save away incomplete line. */

        if (self->s) {
            /* Need to join with buffered value. */

            int m = 0;
            int n = 0;

            m = strlen(self->s);
            n = strlen(p);

            self->s = (char *)realloc(self->s, m+n+1);
            strncpy(self->s+m, p, n);
            self->s[m+n] = '\0';
        }
        else {
            self->s = (char *)malloc(strlen(p)+1);
            strcpy(self->s, p);
        }
    }
}

static PyObject *Log_write(LogObject *self, PyObject *args)
{
    const char *msg = NULL;

    if (!PyArg_ParseTuple(args, "s:write", &msg))
        return NULL;

    if (*msg)
        Log_output(self, msg);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Log_writelines(LogObject *self, PyObject *args)
{
    PyObject *sequence = NULL;
    PyObject *iterator = NULL;
    PyObject *item = NULL;
    const char *msg = NULL;

    if (!PyArg_ParseTuple(args, "O:writelines", &sequence))
        return NULL;

    iterator = PyObject_GetIter(sequence);

    if (iterator == NULL)
        return NULL;

    while ((item = PyIter_Next(iterator))) {
        msg = PyString_AsString(item);

        if (msg) {
            Log_output(self, msg);

            Py_DECREF(item);
        }
        else {
            Py_DECREF(item);

            break;
        }
    }

    Py_DECREF(iterator);

    if (item && !msg)
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef Log_methods[] = {
    { "flush",      (PyCFunction)Log_flush,      METH_VARARGS, 0},
    { "write",      (PyCFunction)Log_write,      METH_VARARGS, 0},
    { "writelines", (PyCFunction)Log_writelines, METH_VARARGS, 0},
    { NULL, NULL}
};

static PyTypeObject Log_Type = {
    /* The ob_type field must be initialized in the module init function
     * to be portable to Windows without using C++. */
    PyObject_HEAD_INIT(NULL)
    0,                      /*ob_size*/
    "mod_wsgi.Log",         /*tp_name*/
    sizeof(LogObject),      /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Log_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    Log_methods,            /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

typedef struct {
        PyObject_HEAD
        request_rec *r;
        int init;
        int done;
        char *buffer;
        apr_size_t size;
        apr_size_t offset;
        apr_size_t length;
} InputObject;

static PyTypeObject Input_Type;

static InputObject *newInputObject(request_rec *r)
{
    InputObject *self;

    self = PyObject_New(InputObject, &Input_Type);
    if (self == NULL)
        return NULL;

    self->r = r;
    self->init = 0;
    self->done = 0;

    self->buffer = NULL;
    self->size = 0;
    self->offset = 0;
    self->length = 0;

    return self;
}

static void Input_dealloc(InputObject *self)
{
    if (self->buffer)
        free(self->buffer);

    PyObject_Del(self);
}

static PyObject *Input_close(InputObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ":close"))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *Input_read(InputObject *self, PyObject *args)
{
    long size = -1;

    PyObject *result = NULL;
    char *buffer = NULL;
    apr_size_t length = 0;

    apr_size_t n;

    if (!PyArg_ParseTuple(args, "|l:read", &size))
        return NULL;

    if (!self->init) {
        if (!ap_should_client_block(self->r))
            self->done = 1;

        self->init = 1;
    }

    /*
     * No point continuing if requested size is zero or if no
     * more data to read and no buffered data.
     */

    if ((self->done && self->length == 0) || size == 0)
        return PyString_FromString("");

    /*
     * If size is not specified for the number of bytes
     * to read in, default to reading in standard Apache
     * block size.
     */

    if (size < 0)
        size = HUGE_STRING_LEN;

    /* Allocate string of the exact size required. */

    result = PyString_FromStringAndSize(NULL, size);

    if (!result)
        return NULL;

    buffer = PyString_AS_STRING((PyStringObject *)result);

    /* Copy any residual data from use of readline(). */

    if (self->buffer && self->length) {
        if (size >= self->length) {
            length = self->length;
            memcpy(buffer, self->buffer + self->offset, length);
            self->offset = 0;
            self->length = 0;
        }
        else {
            length = size;
            memcpy(buffer, self->buffer + self->offset, length);
            self->offset += length;
            self->length -= length;
        }
    }

    /* If all data residual buffer consumed then free it. */

    if (!self->length) {
        free(self->buffer);
        self->buffer = NULL;
    }

    /*
     * Read in remaining data required to achieve size. If
     * requested size of data wasn't able to be read in just
     * return what was able to be read. Robust applications
     * should keep reading until no data returned, not until
     * the size of the data isn't what was requested.
     */

    if (length < size) {
        Py_BEGIN_ALLOW_THREADS
        n = ap_get_client_block(self->r, buffer + length, size - length);
        Py_END_ALLOW_THREADS

        if (n == -1) {
            PyErr_SetString(PyExc_IOError, "request data read error");
            Py_DECREF(result);
            return NULL;
        }
        else if (n == 0) {
            /* Have exhausted all the available input data. */

            self->done = 1;
        }

        length += n;

        /*
         * Resize the final string. If the size reduction is
         * by more than 25% of the string size, then Python
         * will allocate a new block of memory and copy the
         * data into it.
         */

        if (length != size) {
            if (_PyString_Resize(&result, length))
                return NULL;
        }
    }

    return result;
}

static PyObject *Input_readline(InputObject *self, PyObject *args)
{
    long size = -1;

    PyObject *result = NULL;
    char *buffer = NULL;
    apr_size_t length = 0;

    apr_size_t n;

    if (!PyArg_ParseTuple(args, "|l:readline", &size))
        return NULL;

    if (!self->init) {
        if (!ap_should_client_block(self->r))
            self->done = 1;

        self->init = 1;
    }

    /*
     * No point continuing if requested size is zero or if no
     * more data to read and no buffered data.
     */

    if ((self->done && self->length == 0) || size == 0)
        return PyString_FromString("");

    /*
     * First deal with case where size has been specified. After
     * that deal with case where expected that a complete line
     * is returned regardless of the size.
     */

    if (size > 0) {
        /* Allocate string of the exact size required. */

        result = PyString_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyString_AS_STRING((PyStringObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length) {
            char *p = NULL;
            const char *q = NULL;

            p = buffer;
            q = self->buffer + self->offset;

            while (self->length && length < size) {
                self->offset++;
                self->length--;
                length++;
                if ((*p++ = *q++) == '\n')
                    break;
            }

            /* If all data in residual buffer consumed then free it. */

            if (!self->length) {
                free(self->buffer);
                self->buffer = NULL;
            }
        }

        /*
         * Read in remaining data required to achieve size. Note
         * that can't just return whatever the first read might
         * have returned if no EOL encountered as must return
         * exactly the required size if no EOL unless that would
         * have exhausted all input.
         */

        while ((!length || buffer[length-1] != '\n') &&
               !self->done && length < size) {

            char *p = NULL;
            char *q = NULL;

            Py_BEGIN_ALLOW_THREADS
            n = ap_get_client_block(self->r, buffer + length, size - length);
            Py_END_ALLOW_THREADS

            if (n == -1) {
                PyErr_SetString(PyExc_IOError, "request data read error");
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0) {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }
            else {
                /*
                 * Search for embedded EOL in what was read and if
                 * found copy any residual into a buffer for use
                 * next time the read functions are called.
                 */

                p = buffer + length;
                q = p + n;

                while (p != q) {
                    length++;
                    if (*p++ == '\n')
                        break;
                }

                if (p != q) {
                    self->size = q - p;
                    self->buffer = (char *)malloc(self->size);
                    self->offset = 0;
                    self->length = self->size;

                    memcpy(self->buffer, p, self->size);
                }
            }
        }

        /*
         * Resize the final string. If the size reduction is
         * by more than 25% of the string size, then Python
         * will allocate a new block of memory and copy the
         * data into it.
         */

        if (length != size) {
            if (_PyString_Resize(&result, length))
                return NULL;
        }
    }
    else {
        /*
         * Here we have to read in a line but where we have no
         * idea how long it may be. What we can do first is if
         * we have any residual data from a previous read
         * operation, see if it contains an EOL. This means we
         * have to do a search, but this is likely going to be
         * better than having to resize and copy memory later on.
         */

        if (self->buffer && self->length) {
            const char *p = NULL;
            const char *q = NULL;

            p = self->buffer + self->offset;
            q = memchr(p, '\n', self->length);

            if (q)
                size = q - p;
        }

        /*
         * If residual data buffer didn't contain an EOL, all we
         * can do is allocate a reasonably sized string and if
         * that isn't big enough keep increasing it in size. For
         * this we will start out with a buffer 25% greater in
         * size than what is stored in the residual data buffer
         * or one the same size as Apache string size, whichever
         * is greater.
         */

        if (self->buffer && size < 0) {
            size = self->length;
            size = size + (size >> 2);
        }

        if (size < HUGE_STRING_LEN)
            size = HUGE_STRING_LEN;

        /* Allocate string of the initial size. */

        result = PyString_FromStringAndSize(NULL, size);

        if (!result)
            return NULL;

        buffer = PyString_AS_STRING((PyStringObject *)result);

        /* Copy any residual data from use of readline(). */

        if (self->buffer && self->length) {
            char *p = NULL;
            const char *q = NULL;

            p = buffer;
            q = self->buffer + self->offset;

            while (self->length && length < size) {
                self->offset++;
                self->length--;
                length++;
                if ((*p++ = *q++) == '\n')
                    break;
            }

            /* If all data in residual buffer consumed then free it. */

            if (!self->length) {
                free(self->buffer);
                self->buffer = NULL;
            }
        }

        /*
         * Read in remaining data until find an EOL, or until all
         * data has been consumed.
         */

        while ((!length || buffer[length-1] != '\n') && !self->done) {

            char *p = NULL;
            char *q = NULL;

            Py_BEGIN_ALLOW_THREADS
            n = ap_get_client_block(self->r, buffer + length, size - length);
            Py_END_ALLOW_THREADS

            if (n == -1) {
                PyErr_SetString(PyExc_IOError, "request data read error");
                Py_DECREF(result);
                return NULL;
            }
            else if (n == 0) {
                /* Have exhausted all the available input data. */

                self->done = 1;
            }
            else {
                /*
                 * Search for embedded EOL in what was read and if
                 * found copy any residual into a buffer for use
                 * next time the read functions are called.
                 */

                p = buffer + length;
                q = p + n;

                while (p != q) {
                    length++;
                    if (*p++ == '\n')
                        break;
                }

                if (p != q) {
                    self->size = q - p;
                    self->buffer = (char *)malloc(self->size);
                    self->offset = 0;
                    self->length = self->size;

                    memcpy(self->buffer, p, self->size);
                }

                if (buffer[length-1] != '\n') {
                    /* Increase size of string and keep going. */

                    size = size + (size >> 2);

                    if (_PyString_Resize(&result, size))
                        return NULL;

                    buffer = PyString_AS_STRING((PyStringObject *)result);
                }
            }
        }

        /*
         * Resize the final string. If the size reduction is by
         * more than 25% of the string size, then Python will
         * allocate a new block of memory and copy the data into
         * it.
         */

        if (length != size) {
            if (_PyString_Resize(&result, length))
                return NULL;
        }
    }

    return result;
}

static PyObject *Input_readlines(InputObject *self, PyObject *args)
{
    long hint = 0;
    long length = 0;

    PyObject *result = NULL;
    PyObject *line = NULL;
    PyObject *rlargs = NULL;

    if (!PyArg_ParseTuple(args, "|l:readlines", &hint))
        return NULL;

    result = PyList_New(0);
    if (!result)
        return NULL;

    rlargs = PyTuple_New(0);
    if (!rlargs) {
        Py_DECREF(result);
        return NULL;
    }

    while (1) {
        int n;

        if (!(line = Input_readline(self, rlargs))) {
            Py_DECREF(result);
            result = NULL;
            break;
        }

        if ((n = PyString_Size(line)) == 0) {
            Py_DECREF(line);
            break;
        }

        if (PyList_Append(result, line) == -1) {
            Py_DECREF(line);
            Py_DECREF(result);
            result = NULL;
            break;
        }

        Py_DECREF(line);

        length += n;
        if (hint > 0 && length >= hint)
            break;
    }

    Py_DECREF(rlargs);

    return result;
}

static PyMethodDef Input_methods[] = {
    { "close",     (PyCFunction)Input_close,     METH_VARARGS, 0},
    { "read",      (PyCFunction)Input_read,      METH_VARARGS, 0},
    { "readline",  (PyCFunction)Input_readline,  METH_VARARGS, 0},
    { "readlines", (PyCFunction)Input_readlines, METH_VARARGS, 0},
    { NULL, NULL}
};

static PyObject *Input_iter(InputObject *self)
{
    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *Input_iternext(InputObject *self)
{
    PyObject *line = NULL;
    PyObject *rlargs = NULL;

    rlargs = PyTuple_New(0);

    if (!rlargs)
      return NULL;

    line = Input_readline(self, rlargs);

    Py_DECREF(rlargs);

    if (!line)
        return NULL;

    if (PyString_GET_SIZE(line) == 0) {
        PyErr_SetObject(PyExc_StopIteration, Py_None);
        Py_DECREF(line);
        return NULL;
    }

    return line;
}

static PyTypeObject Input_Type = {
    /* The ob_type field must be initialized in the module init function
     * to be portable to Windows without using C++. */
    PyObject_HEAD_INIT(NULL)
    0,                      /*ob_size*/
    "mod_wsgi.Input",       /*tp_name*/
    sizeof(InputObject),    /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Input_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER, /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    (getiterfunc)Input_iter, /*tp_iter*/
    (iternextfunc)Input_iternext, /*tp_iternext*/
    Input_methods,          /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

typedef struct {
        PyObject_HEAD
        request_rec *r;
        WSGIRequestConfig *config;
        int status;
        PyObject *headers;
        PyObject *sequence;
        LogObject *log;
} AdapterObject;

static PyTypeObject Adapter_Type;

static AdapterObject *newAdapterObject(request_rec *r, LogObject *log)
{
    AdapterObject *self;

    self = PyObject_New(AdapterObject, &Adapter_Type);
    if (self == NULL)
        return NULL;

    self->r = r;

    self->config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                             &wsgi_module);

    self->status = -1;
    self->headers = NULL;
    self->sequence = NULL;

    self->log = log;
    Py_INCREF(self->log);

    return self;
}

static void Adapter_dealloc(AdapterObject *self)
{
    Py_XDECREF(self->headers);
    Py_XDECREF(self->sequence);

    Py_DECREF(self->log);

    PyObject_Del(self);
}

static PyObject *Adapter_start(AdapterObject *self, PyObject *args)
{
    const char *status = NULL;
    PyObject *headers = NULL;
    PyObject *exc_info = NULL;

    char* value = NULL;

    if (!PyArg_ParseTuple(args, "sO|O:start_response",
        &status, &headers, &exc_info)) {
        return NULL;
    }

    if (!PyList_Check(headers)) {
        PyErr_SetString(PyExc_TypeError, "response headers must be a list");
        return NULL;
    }

    if (exc_info && exc_info != Py_None) {
        if (self->status != -1 && !self->headers) {
            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (!PyArg_ParseTuple(exc_info, "OOO", &type, &value, &traceback))
                return NULL;

            PyErr_Restore(type, value, traceback);

            return NULL;
        }
    }
    else if (self->status != -1 && !self->headers) {
        PyErr_SetString(PyExc_TypeError, "headers have already been sent");
        return NULL;
    }

    value = ap_getword(self->r->pool, &status, ' ');

    self->status = strtol(value, &value, 10);

    if (*value || errno == ERANGE) {
        PyErr_SetString(PyExc_TypeError, "status value is not an integer");
        return NULL;
    }

    if (!*status) {
        PyErr_SetString(PyExc_TypeError, "status message was not supplied");
        return NULL;
    }

    Py_XDECREF(self->headers);

    self->headers = headers;

    Py_INCREF(self->headers);

    return PyObject_GetAttrString((PyObject *)self, "write");
}

static int Adapter_output(AdapterObject *self,
                                  const char *data, int length)
{
    int i = 0;
    char *name = NULL;
    char *value = NULL;

    if (self->status == -1) {
        PyErr_SetString(PyExc_TypeError, "response has not been started");
        return 0;
    }

    if (self->headers) {
        int set = 0;

        self->r->status = self->status;

        for (i=0; i<PyList_Size(self->headers); i++) {
            if (!PyArg_ParseTuple(PyList_GetItem(self->headers, i),
                "ss", &name, &value)) {
                PyErr_SetString(PyExc_TypeError, "headers must be strings");
                return 0;
            }

            if (!strcasecmp(name, "Content-Type")) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                self->r->content_type = apr_pstrdup(self->r->pool, value);
#else
                ap_set_content_type(self->r, value);
#endif
            }
            else if (!strcasecmp(name, "Content-Length")) {
                char *v = value;
                long l = 0;

                l = strtol(v, &v, 10);
                if (*v) {
                    PyErr_SetString(PyExc_TypeError, "invalid content length");
                    return 0;
                }

                ap_set_content_length(self->r, l);

                set = 1;
            }
            else {
                if (self->status != HTTP_OK)
                    apr_table_set(self->r->err_headers_out, name, value);
                else
                    apr_table_set(self->r->headers_out, name, value);
            }
        }

        /*
         * If content length not set and dealing with iterable
         * response from application, see if response is a
         * sequence consisting of only one item and if so use
         * the current length of data being output as the
         * content length to use.
         */

        if (!set && self->sequence) {
            if (PySequence_Check(self->sequence)) {
                if (PySequence_Size(self->sequence) == 1)
                    ap_set_content_length(self->r, length);

                if (PyErr_Occurred())
                    PyErr_Clear();
            }
        }

        ap_send_http_header(self->r);

        Py_DECREF(self->headers);
        self->headers = NULL;
    }

    if (length) {
        ap_rwrite(data, length, self->r);
        if (!self->config->output_buffering)
            ap_rflush(self->r);
    }

    return 1;
}

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *wsgi_is_https = NULL;
#endif

static PyObject *Adapter_environ(AdapterObject *self)
{
    request_rec *r = NULL;

    PyObject *environ = NULL;
    PyObject *object = NULL;

    const apr_array_header_t *head = NULL;
    const apr_table_entry_t *elts = NULL;

    int i = 0;

    const char *location = NULL;

    int multithread = 0;
    int multiprocess = 0;

    const char *scheme = NULL;

    /* Create the WSGI environment dictionary. */

    environ = PyDict_New();

    /* Merge the CGI environment into the WSGI environment. */

    r = self->r;

    head = apr_table_elts(r->subprocess_env);
    elts = (apr_table_entry_t *)head->elts;

    for (i = 0; i < head->nelts; ++i) {
        if (elts[i].key) {
            if (elts[i].val) {
                object = PyString_FromString(elts[i].val);
                PyDict_SetItemString(environ, elts[i].key, object);
                Py_DECREF(object);
            }
            else
                PyDict_SetItemString(environ, elts[i].key, Py_None);
        }
    }

    /* Now setup all the WSGI specific environment values. */

    object = Py_BuildValue("(ii)", 1, 0);
    PyDict_SetItemString(environ, "wsgi.version", object);
    Py_DECREF(object);

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    ap_mpm_query(AP_MPMQ_IS_THREADED, &multithread);
    multithread = (multithread != AP_MPMQ_NOT_SUPPORTED);

    ap_mpm_query(AP_MPMQ_IS_FORKED, &multiprocess);
    if (multiprocess != AP_MPMQ_NOT_SUPPORTED) {
        ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &multiprocess);
        multiprocess = (multiprocess != 1);
    }
#else
    multiprocess = 1;
#endif

    object = PyBool_FromLong(multithread);
    PyDict_SetItemString(environ, "wsgi.multithread", object);
    Py_DECREF(object);

    object = PyBool_FromLong(multiprocess);
    PyDict_SetItemString(environ, "wsgi.multiprocess", object);
    Py_DECREF(object);

    PyDict_SetItemString(environ, "wsgi.run_once", Py_False);

    scheme = apr_table_get(r->subprocess_env, "HTTPS");

    if (scheme && (!strcasecmp(scheme, "On") || !strcmp(scheme, "1"))) {
        object = PyString_FromString("https");
        PyDict_SetItemString(environ, "wsgi.url_scheme", object);
        Py_DECREF(object);
    }
    else {
        object = PyString_FromString("http");
        PyDict_SetItemString(environ, "wsgi.url_scheme", object);
        Py_DECREF(object);
    }

    /*
     * Setup log object for WSGI errors. Don't decrement
     * reference to log object as keep reference to it.
     */

    object = (PyObject *)self->log;
    PyDict_SetItemString(environ, "wsgi.errors", object);

    /* Setup input object for request content. */

    object = (PyObject *)newInputObject(r);
    PyDict_SetItemString(environ, "wsgi.input", object);
    Py_DECREF(object);

    /* Now setup some mod_wsgi specific environment values. */

    object = PyString_FromString(self->config->process_name);
    PyDict_SetItemString(environ, "mod_wsgi.process_name", object);
    Py_DECREF(object);

    object = PyString_FromString(self->config->application_group);
    PyDict_SetItemString(environ, "mod_wsgi.application_group", object);
    Py_DECREF(object);

    object = PyString_FromString(self->config->callable_object);
    PyDict_SetItemString(environ, "mod_wsgi.callable_object", object);
    Py_DECREF(object);

    object = PyBool_FromLong(self->config->script_reloading);
    PyDict_SetItemString(environ, "mod_wsgi.script_reloading", object);
    Py_DECREF(object);

    object = PyInt_FromLong(self->config->reload_mechanism);
    PyDict_SetItemString(environ, "mod_wsgi.reload_mechanism", object);
    Py_DECREF(object);

    object = PyBool_FromLong(self->config->output_buffering);
    PyDict_SetItemString(environ, "mod_wsgi.output_buffering", object);
    Py_DECREF(object);

    return environ;
}

static int Adapter_run(AdapterObject *self, PyObject *object)
{
    int result = HTTP_INTERNAL_SERVER_ERROR;

    PyObject *environ = NULL;
    PyObject *start = NULL;
    PyObject *args = NULL;
    PyObject *iterator = NULL;
    PyObject *close = NULL;

    const char *msg = NULL;
    int length = 0;

    environ = Adapter_environ(self);

    start = PyObject_GetAttrString((PyObject *)self, "start_response");

    args = Py_BuildValue("(OO)", environ, start);

    self->sequence = PyEval_CallObject(object, args);

    if (self->sequence != NULL) {
        iterator = PyObject_GetIter(self->sequence);

        if (iterator != NULL) {
            PyObject *item = NULL;

            while ((item = PyIter_Next(iterator))) {
                msg = PyString_AsString(item);
                length = PyString_Size(item);

                if (!msg || !Adapter_output(self, msg, length)) {
                    Py_DECREF(item);
                    break;
                }

                Py_DECREF(item);
            }

            if (!PyErr_Occurred()) {
                if (Adapter_output(self, "", 0))
                    result = OK;
            }

            Py_DECREF(iterator);
        }

        if (PyObject_HasAttrString(self->sequence, "close")) {
            PyObject *args = NULL;
            PyObject *data = NULL;

            close = PyObject_GetAttrString(self->sequence, "close");

            args = Py_BuildValue("()");
            data = PyEval_CallObject(close, args);

            Py_DECREF(args);
            Py_XDECREF(data);
            Py_DECREF(close);
        }

        Py_DECREF(self->sequence);

        self->sequence = NULL;
    }

    Py_DECREF(args);
    Py_DECREF(start);
    Py_DECREF(environ);

    return result;
}

static PyObject *Adapter_write(AdapterObject *self, PyObject *args)
{
    const char *data = NULL;
    int length = 0;

    if (!PyArg_ParseTuple(args, "s#:write", &data, &length))
        return NULL;

    if (!Adapter_output(self, data, length))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef Adapter_methods[] = {
    { "start_response", (PyCFunction)Adapter_start, METH_VARARGS, 0},
    { "write",          (PyCFunction)Adapter_write, METH_VARARGS, 0},
    { NULL, NULL}
};

static PyTypeObject Adapter_Type = {
    /* The ob_type field must be initialized in the module init function
     * to be portable to Windows without using C++. */
    PyObject_HEAD_INIT(NULL)
    0,                      /*ob_size*/
    "mod_wsgi.Adapter",     /*tp_name*/
    sizeof(AdapterObject),  /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Adapter_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    Adapter_methods,        /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/* Restricted object to stop access to STDIN/STDOUT. */

typedef struct {
    PyObject_HEAD
    const char *s;
} RestrictedObject;

static PyTypeObject Restricted_Type;

static RestrictedObject *newRestrictedObject(const char *s)
{
    RestrictedObject *self;

    self = PyObject_New(RestrictedObject, &Restricted_Type);
    if (self == NULL)
        return NULL;

    self->s = s;

    return self;
}

static void Restricted_dealloc(RestrictedObject *self)
{
    PyObject_Del(self);
}

static PyObject *Restricted_getattr(RestrictedObject *self, char *name)
{
    PyErr_Format(PyExc_IOError, "%s access restricted by mod_wsgi", self->s);

    return NULL;
}

static PyTypeObject Restricted_Type = {
    /* The ob_type field must be initialized in the module init function
     * to be portable to Windows without using C++. */
    PyObject_HEAD_INIT(NULL)
    0,                      /*ob_size*/
    "mod_wsgi.Restricted",  /*tp_name*/
    sizeof(RestrictedObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Restricted_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    (getattrfunc)Restricted_getattr, /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/* Function to restrict access to use of signal(). */

static PyObject *wsgi_signal_intercept(PyObject *self, PyObject *args)
{
    PyObject *h = NULL;
    int n = 0;

    PyObject *m = NULL;

    if (!PyArg_ParseTuple(args, "iO:signal", &n, &h))
        return NULL;

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                 "mod_wsgi (pid=%d): Callback registration for "
                 "signal %d ignored.", getpid(), n);
#else
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                 "mod_wsgi (pid=%d): Callback registration for "
                 "signal %d ignored.", getpid(), n);
#endif

    m = PyImport_ImportModule("traceback");

    if (m) {
        PyObject *d = NULL;
        PyObject *o = NULL;
        d = PyModule_GetDict(m);
        o = PyDict_GetItemString(d, "print_stack");
        if (o) {
            PyObject *log = NULL;
            PyObject *args = NULL;
            PyObject *result = NULL;
            Py_INCREF(o);
            log = (PyObject *)newLogObject(NULL);
            args = Py_BuildValue("(OOO)", Py_None, Py_None, log);
            result = PyEval_CallObject(o, args);
            Py_XDECREF(result);
            Py_DECREF(args);
            Py_DECREF(log);
        }
        Py_DECREF(o);
    }

    Py_INCREF(m);

    Py_INCREF(h);

    return h;
}

static PyMethodDef wsgi_signal_method[] = {
    { "signal", (PyCFunction)wsgi_signal_intercept, METH_VARARGS, 0 },
    { NULL, NULL }
};

/* Wrapper around Python interpreter instances. */

typedef struct {
    PyObject_HEAD
    char *name;
    PyInterpreterState *interp;
    int owner;
} InterpreterObject;

static PyTypeObject Interpreter_Type;

static InterpreterObject *newInterpreterObject(const char *name,
                                               PyInterpreterState *interp)
{
    InterpreterObject *self;
    PyThreadState *tstate = NULL;
    PyThreadState *save_tstate = NULL;
    PyObject *module = NULL;
    PyObject *object = NULL;
    PyObject *item = NULL;

    self = PyObject_New(InterpreterObject, &Interpreter_Type);
    if (self == NULL)
        return NULL;

    /* Remember active thread state so can restore it. */

    save_tstate = PyThreadState_Swap(NULL);

    /* Save away the interpreter name. */

    self->name = strdup(name);

    if (interp) {
        /*
         * Interpreter provided to us so will not be
         * responsible for deleting it later.
         */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi (pid=%d): Attach interpreter '%s'.",
                     getpid(), name);
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi (pid=%d): Attach interpreter '%s'.",
                     getpid(), name);
#endif

        self->interp = interp;
        self->owner = 0;

        /*
         * Need though now to create a thread state
         * against the interpreter so we can preload
         * it with our modules and fixups.
         */

        tstate = PyThreadState_New(self->interp);
        PyThreadState_Swap(tstate);
    }
    else {
        /*
         * Create the interpreter. If creation of the
         * interpreter fails it will restore the
         * existing active thread state for us so don't
         * need to worry about it in that case.
         */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi (pid=%d): Create interpreter '%s'.",
                     getpid(), name);
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi (pid=%d): Create interpreter '%s'.",
                     getpid(), name);
#endif

        tstate = Py_NewInterpreter();

        if (!tstate) {
            PyErr_SetString(PyExc_RuntimeError, "Py_NewInterpreter() failed");

            Py_DECREF(self);

            return NULL;
        }

        self->interp = tstate->interp;
        self->owner = 1;
    }

    /*
     * Create mod_wsgi Python module. Only put the
     * version in this for now. Might use it later
     * on for interpreter specific information.
     */

    module = PyImport_AddModule("mod_wsgi");

    PyModule_AddObject(module, "version", Py_BuildValue("(ii)",
                       MOD_WSGI_MAJORVERSION_NUMBER,
                       MOD_WSGI_MINORVERSION_NUMBER));

    /*
     * Install restricted objects for STDIN and STDOUT,
     * or log object for STDOUT as appropriate.
     */

    object = (PyObject *)newLogObject(NULL);
    PySys_SetObject("stderr", object);
    Py_DECREF(object);

    if (wsgi_server_config->restrict_stdout != 0) {
        object = (PyObject *)newRestrictedObject("sys.stdout");
        PySys_SetObject("stdout", object);
        Py_DECREF(object);
    }
    else {
        object = (PyObject *)newLogObject(NULL);
        PySys_SetObject("stdout", object);
        Py_DECREF(object);
    }

    if (wsgi_server_config->restrict_stdin != 0) {
        object = (PyObject *)newRestrictedObject("sys.stdin");
        PySys_SetObject("stdin", object);
        Py_DECREF(object);
    }

    /*
     * Set sys.argv to one element list to fake out
     * modules that look there for Python command
     * line arguments as appropriate.
     */

    object = PyList_New(0);
    item = PyString_FromString("mod_wsgi");
    PyList_Append(object, item);
    PySys_SetObject("argv", object);
    Py_DECREF(item);
    Py_DECREF(object);

    /*
     * Install intercept for signal handler registration
     * if appropriate.
     */

    if (wsgi_server_config->restrict_signal != 0) {
        module = PyImport_ImportModule("signal");
        PyModule_AddObject(module, "signal", PyCFunction_New(
                           &wsgi_signal_method[0], NULL));
        Py_DECREF(module);
    }

    PyThreadState_Clear(tstate);
    PyThreadState_Swap(save_tstate);
    PyThreadState_Delete(tstate);

    return self;
}

static void Interpreter_dealloc(InterpreterObject *self)
{
    PyThreadState *tstate = NULL;
    PyObject *exitfunc = NULL;
    PyObject *module = NULL;

    /*
     * We should always enter here with the Python GIL held, but
     * there will be no active thread state. Note that it should
     * be safe to always assume that the simplified GIL state
     * API lock was originally unlocked as always calling in
     * from an Apache thread outside of Python.
     */

    PyEval_ReleaseLock();

    if (*self->name) {
        tstate = PyThreadState_New(self->interp);
        PyEval_AcquireThread(tstate);
    }
    else
        PyGILState_Ensure();

    if (self->owner) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi (pid=%d): Destroy interpreter '%s'.",
                     getpid(), self->name);
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi (pid=%d): Destroy interpreter '%s'.",
                     getpid(), self->name);
#endif
    }
    else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi (pid=%d): Cleanup interpreter '%s'.",
                     getpid(), self->name);
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi (pid=%d): Cleanup interpreter '%s'.",
                     getpid(), self->name);
#endif
    }

    /*
     * Because the thread state we are using was created outside
     * of any Python code and is not the same as the Python main
     * thread, there is no record of it within the 'threading'
     * module. We thus need to call the 'currentThread()'
     * function of the 'threading' module to force it to create
     * a thread handle for the thread. If we do not do this,
     * then the 'threading' modules exit function will always
     * fail because it will not be able to find a handle for
     * this thread.
     */

    module = PyImport_ImportModule("threading");

    if (!module)
        PyErr_Clear();

    if (module) {
        PyObject *dict = NULL;
        PyObject *func = NULL;
        PyObject *handle = NULL;

        dict = PyModule_GetDict(module);
        func = PyDict_GetItemString(dict, "currentThread");
        if (func) {
            PyObject *args = NULL;
            PyObject *res = NULL;
            Py_INCREF(func);
            res = PyEval_CallObject(func, (PyObject *)NULL);
            if (!res) {
                PyErr_Clear();
            }
            Py_XDECREF(res);
            Py_DECREF(func);
        }
    }

    /*
     * In Python 2.5.1 an exit function is no longer used to
     * shutdown and wait on non daemon threads which were created
     * from Python code. Instead, in Py_Main() it explicitly
     * calls 'threading._shutdown()'. Thus need to emulate this
     * behaviour for those versions.
     */

    if (module) {
        PyObject *dict = NULL;
        PyObject *func = NULL;
        PyObject *handle = NULL;

        dict = PyModule_GetDict(module);
        func = PyDict_GetItemString(dict, "_shutdown");
        if (func) {
            PyObject *args = NULL;
            PyObject *res = NULL;
            Py_INCREF(func);
            res = PyEval_CallObject(func, (PyObject *)NULL);

            if (res == NULL) {
                PyObject *m = NULL;
                PyObject *result = NULL;

                PyObject *type = NULL;
                PyObject *value = NULL;
                PyObject *traceback = NULL;

#if AP_SERVER_MAJORVERSION_NUMBER < 2
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, "mod_wsgi (pid=%d): Exception occurred "
                             "within threading._shutdown().",
                             getpid());
#else
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, 0, "mod_wsgi (pid=%d): Exception occurred "
                             "within threading._shutdown().",
                             getpid());
#endif

                PyErr_Fetch(&type, &value, &traceback);

                if (!value) {
                    value = Py_None;
                    Py_INCREF(value);
                }

                if (!traceback) {
                    traceback = Py_None;
                    Py_INCREF(traceback);
                }

                m = PyImport_ImportModule("traceback");

                if (m) {
                    PyObject *d = NULL;
                    PyObject *o = NULL;
                    d = PyModule_GetDict(m);
                    o = PyDict_GetItemString(d, "print_exception");
                    if (o) {
                        PyObject *log = NULL;
                        PyObject *args = NULL;
                        Py_INCREF(o);
                        log = (PyObject *)newLogObject(NULL);
                        args = Py_BuildValue("(OOOOO)", type, value,
                                             traceback, Py_None, log);
                        result = PyEval_CallObject(o, args);
                        Py_DECREF(args);
                        Py_DECREF(log);
                    }
                    Py_DECREF(o);
                }

                if (!result) {
                    /*
                     * If can't output exception and traceback then
                     * use PyErr_Print to dump out details of the
                     * exception. For SystemExit though if we do
                     * that the process will actually be terminated
                     * so can only clear the exception information
                     * and keep going.
                     */

                    PyErr_Restore(type, value, traceback);

                    if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                        PyErr_Print();
                        if (Py_FlushLine())
                            PyErr_Clear();
                    }
                    else {
                        PyErr_Clear();
                    }
                }
                else {
                    Py_XDECREF(type);
                    Py_XDECREF(value);
                    Py_XDECREF(traceback);
                }

                Py_XDECREF(result);

                Py_DECREF(m);
            }

            Py_XDECREF(res);
            Py_DECREF(func);
        }
    }

    /* Finally done with 'threading' module. */

    if (module)
        Py_DECREF(module);

    /* Invoke exit functions by calling sys.exitfunc(). */

    exitfunc = PySys_GetObject("exitfunc");

    if (exitfunc) {
        PyObject *res = NULL;
        Py_INCREF(exitfunc);
        PySys_SetObject("exitfunc", (PyObject *)NULL);
        res = PyEval_CallObject(exitfunc, (PyObject *)NULL);

        if (res == NULL) {
            PyObject *m = NULL;
            PyObject *result = NULL;

            PyObject *type = NULL;
            PyObject *value = NULL;
            PyObject *traceback = NULL;

            if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, "mod_wsgi (pid=%d): SystemExit "
                             "exception raised by sys.exitfunc() "
                             "ignored.", getpid());
#else
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, 0, "mod_wsgi (pid=%d): SystemExit "
                             "exception raised by sys.exitfunc() "
                             "ignored.", getpid());
#endif
            }
            else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, "mod_wsgi (pid=%d): Exception "
                             "occurred within sys.exitfunc().",
                             getpid());
#else
                ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                             0, 0, "mod_wsgi (pid=%d): Exception "
                             "occurred within sys.exitfunc().",
                             getpid());
#endif
            }

            PyErr_Fetch(&type, &value, &traceback);

            if (!value) {
                value = Py_None;
                Py_INCREF(value);
            }

            if (!traceback) {
                traceback = Py_None;
                Py_INCREF(traceback);
            }

            m = PyImport_ImportModule("traceback");

            if (m) {
                PyObject *d = NULL;
                PyObject *o = NULL;
                d = PyModule_GetDict(m);
                o = PyDict_GetItemString(d, "print_exception");
                if (o) {
                    PyObject *log = NULL;
                    PyObject *args = NULL;
                    Py_INCREF(o);
                    log = (PyObject *)newLogObject(NULL);
                    args = Py_BuildValue("(OOOOO)", type, value,
                                         traceback, Py_None, log);
                    result = PyEval_CallObject(o, args);
                    Py_DECREF(args);
                    Py_DECREF(log);
                }
                Py_DECREF(o);
            }

            if (!result) {
                /*
                 * If can't output exception and traceback then
                 * use PyErr_Print to dump out details of the
                 * exception. For SystemExit though if we do
                 * that the process will actually be terminated
                 * so can only clear the exception information
                 * and keep going.
                 */

                PyErr_Restore(type, value, traceback);

                if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                    PyErr_Print();
                    if (Py_FlushLine())
                        PyErr_Clear();
                }
                else {
                    PyErr_Clear();
                }
            }
            else {
                Py_XDECREF(type);
                Py_XDECREF(value);
                Py_XDECREF(traceback);
            }

            Py_XDECREF(result);

            Py_DECREF(m);
        }

        Py_XDECREF(res);
        Py_DECREF(exitfunc);
    }

    /* If we own it, we destroy it. */

    if (!self->owner) {
        if (*self->name) {
            tstate = PyThreadState_Get();

            PyThreadState_Clear(tstate);
            PyEval_ReleaseThread(tstate);
            PyThreadState_Delete(tstate);
        }
        else
            PyGILState_Release(PyGILState_UNLOCKED);

        PyEval_AcquireLock();
    }
    else
        Py_EndInterpreter(tstate);

    free(self->name);

    PyObject_Del(self);
}

static PyTypeObject Interpreter_Type = {
    /* The ob_type field must be initialized in the module init function
     * to be portable to Windows without using C++. */
    PyObject_HEAD_INIT(NULL)
    0,                      /*ob_size*/
    "mod_wsgi.Interpreter",  /*tp_name*/
    sizeof(InterpreterObject), /*tp_basicsize*/
    0,                      /*tp_itemsize*/
    /* methods */
    (destructor)Interpreter_dealloc, /*tp_dealloc*/
    0,                      /*tp_print*/
    0,                      /*tp_getattr*/
    0,                      /*tp_setattr*/
    0,                      /*tp_compare*/
    0,                      /*tp_repr*/
    0,                      /*tp_as_number*/
    0,                      /*tp_as_sequence*/
    0,                      /*tp_as_mapping*/
    0,                      /*tp_hash*/
    0,                      /*tp_call*/
    0,                      /*tp_str*/
    0,                      /*tp_getattro*/
    0,                      /*tp_setattro*/
    0,                      /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,     /*tp_flags*/
    0,                      /*tp_doc*/
    0,                      /*tp_traverse*/
    0,                      /*tp_clear*/
    0,                      /*tp_richcompare*/
    0,                      /*tp_weaklistoffset*/
    0,                      /*tp_iter*/
    0,                      /*tp_iternext*/
    0,                      /*tp_methods*/
    0,                      /*tp_members*/
    0,                      /*tp_getset*/
    0,                      /*tp_base*/
    0,                      /*tp_dict*/
    0,                      /*tp_descr_get*/
    0,                      /*tp_descr_set*/
    0,                      /*tp_dictoffset*/
    0,                      /*tp_init*/
    0,                      /*tp_alloc*/
    0,                      /*tp_new*/
    0,                      /*tp_free*/
    0,                      /*tp_is_gc*/
};

/*
 * Startup and shutdown of Python interpreter. In mod_wsgi if
 * the Python interpreter hasn't been initialised by another
 * Apache module such as mod_python, we will take control and
 * initialise it. Need to remember that we initialised Python as
 * in doing that we also take responsibility for performing
 * special Python fixups after Apache is forked and child
 * process has run.
 */

static int wsgi_python_initialized = 0;

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
static apr_pool_t *wsgi_server_pool = NULL;
#endif

static void wsgi_python_version(void)
{
    const char *compile = PY_VERSION;
    const char *dynamic = 0;

    dynamic = strtok((char *)Py_GetVersion(), " ");

    if (strcmp(compile, dynamic) != 0) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi: Compiled for Python/%s.", compile);
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi: Runtime using Python/%s.", dynamic);
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi: Python module path '%s'.",
                     Py_GetPath());
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi: Compiled for Python/%s.", compile);
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi: Runtime using Python/%s.", dynamic);
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi: Python module path '%s'.",
                     Py_GetPath());
#endif
    }
}

static apr_status_t wsgi_python_term(void *data)
{
    PyInterpreterState *interp = NULL;
    PyThreadState *tstate = NULL;

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                 "mod_wsgi (pid=%d): Terminating Python.",
                 getpid());
#else
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                 "mod_wsgi (pid=%d): Terminating Python.",
                 getpid());
#endif

    PyEval_AcquireLock();

    interp = PyInterpreterState_Head();
    while (interp->next)
        interp = interp->next;

    tstate = PyThreadState_New(interp);
    PyThreadState_Swap(tstate);

    Py_Finalize();

    PyThreadState_Swap(NULL);

    PyEval_ReleaseLock();

    wsgi_python_initialized = 0;

    return APR_SUCCESS;
}

static void wsgi_python_init(apr_pool_t *p)
{
    WSGIServerConfig *config = NULL;

#if defined(DARWIN) && (AP_SERVER_MAJORVERSION_NUMBER < 2)
    static int initialized = 0;
#else
    static int initialized = 1;
#endif

    /*
     * Check that the version of Python found at
     * runtime is what was used at compilation.
     */

    wsgi_python_version();

    /* Perform initialisation if required. */

    if (!Py_IsInitialized() || !initialized) {
        char buffer[256];
        const char *token = NULL;
        const char *version = NULL;

        /* Check for optimisation flag. */

        if (wsgi_server_config->python_optimize > 0)
            Py_OptimizeFlag = 2;
        else
            Py_OptimizeFlag = 0;

        /* Initialise Python. */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi: Initializing Python.");
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi: Initializing Python.");
#endif

        initialized = 1;

        Py_Initialize();

        /* Record version string with Apache. */

        version = Py_GetVersion();

        token = version;
        while (*token && *token != ' ')
            token++;

        strcpy(buffer, "Python/");
        strncat(buffer, version, token - version);

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_add_version_component(buffer);
#else
        ap_add_version_component(p, buffer);
#endif

        /* Initialise threading. */

        PyEval_InitThreads();
        PyEval_ReleaseLock();

        PyThreadState_Swap(NULL);

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
        /*
         * Trigger destruction of the Python interpreter in the
         * parent process on a restart. Can only do this with
         * Apache 2.0 and later.
         */

        apr_pool_create(&wsgi_server_pool, p);
        apr_pool_tag(wsgi_server_pool, "mod_wsgi server pool");

        apr_pool_cleanup_register(wsgi_server_pool, NULL, wsgi_python_term,
                                  apr_pool_cleanup_null);
#endif

        wsgi_python_initialized = 1;
    }
}

/*
 * Functions for acquiring and subsequently releasing desired
 * Python interpreter instance. When acquiring the interpreter
 * a new interpreter instance will be created on demand if it
 * is required. The Python GIL will be held on return when the
 * interpreter is acquired.
 */

#if APR_HAS_THREADS
static apr_thread_mutex_t* wsgi_interp_lock = NULL;
static apr_thread_mutex_t* wsgi_module_lock = NULL;
#endif

static PyObject *wsgi_interpreters = NULL;

static InterpreterObject *wsgi_acquire_interpreter(const char *name)
{
    PyThreadState *tstate = NULL;
    PyInterpreterState *interp = NULL;
    InterpreterObject *handle = NULL;

    /*
     * In a multithreaded MPM must protect the
     * interpreters table. This lock is only needed to
     * avoid a secondary thread coming in and creating
     * the same interpreter if Python releases the GIL
     * when an interpreter is being created. When
     * are removing an interpreter from the table in
     * preparation for reloading, don't need to have
     * it.
     */

#if APR_HAS_THREADS
    apr_thread_mutex_lock(wsgi_interp_lock);
#endif

    /*
     * This function should never be called when the
     * Python GIL is held, so need to acquire it.
     */

    PyEval_AcquireLock();

    /*
     * Check if already have interpreter instance and
     * if not need to create one.
     */

    handle = (InterpreterObject *)PyDict_GetItemString(wsgi_interpreters,
                                                       name);

    if (!handle) {
        handle = newInterpreterObject(name, NULL);

        if (!handle)
            return NULL;

        PyDict_SetItemString(wsgi_interpreters, name, (PyObject *)handle);
    }
    else
        Py_INCREF(handle);

    interp = handle->interp;

    /*
     * Create new thread state object. We should only be
     * getting called where no current active thread
     * state, so no need to remember the old one. When
     * working with the main Python interpreter always
     * use the simplified API for GIL locking so any
     * extension modules which use that will still work.
     */

    PyEval_ReleaseLock();

    if (*name) {
        tstate = PyThreadState_New(interp);
        PyEval_AcquireThread(tstate);
    }
    else
        PyGILState_Ensure();

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_interp_lock);
#endif

    return handle;
}

static void wsgi_remove_interpreter(const char *name)
{
    PyDict_DelItemString(wsgi_interpreters, name);
}

static void wsgi_release_interpreter(InterpreterObject *handle)
{
    PyThreadState *tstate = NULL;

    /*
     * Need to release and destroy the thread state that
     * was created against the interpreter. This will
     * release the GIL. Note that it should be safe to
     * always assume that the simplified GIL state API
     * lock was originally unlocked as always calling in
     * from an Apache thread when we acquire the
     * interpreter in the first place.
     */

    if (*handle->name) {
        tstate = PyThreadState_Get();

        PyThreadState_Clear(tstate);
        PyEval_ReleaseThread(tstate);
        PyThreadState_Delete(tstate);
    }
    else
        PyGILState_Release(PyGILState_UNLOCKED);

    /*
     * Need to reacquire the Python GIL just so we can
     * decrement our reference count to the interpreter
     * itself. If the interpreter has since been removed
     * from the table of interpreters this will result
     * in its destruction if its the last reference.
     */

    PyEval_AcquireLock();

    Py_DECREF(handle);

    PyEval_ReleaseLock();
}

/*
 * Code for importing a module from source by absolute path.
 */

static PyObject *wsgi_load_source(request_rec *r, const char *name, int found)
{
    WSGIRequestConfig *config = NULL;

    FILE *fp = NULL;
    PyObject *m = NULL;
    PyObject *co = NULL;
    struct _node *n = NULL;

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    if (found) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi (pid=%d, process='%s', group='%s'): "
                     "Reloading WSGI script '%s'.", getpid(),
                     config->process_name, config->application_group,
                     r->filename);
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi (pid=%d, process='%s', group='%s'): "
                     "Reloading WSGI script '%s'.", getpid(),
                     config->process_name, config->application_group,
                     r->filename);
#endif
    }
    else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0,
                     "mod_wsgi (pid=%d, process='%s', group='%s'): "
                     "Loading WSGI script '%s'.", getpid(),
                     config->process_name, config->application_group,
                     r->filename);
#else
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, 0,
                     "mod_wsgi (pid=%d, process='%s', group='%s'): "
                     "Loading WSGI script '%s'.", getpid(),
                     config->process_name, config->application_group,
                     r->filename);
#endif
    }

    if (!(fp = fopen(r->filename, "r"))) {
        PyErr_SetFromErrno(PyExc_IOError);
        return NULL;
    }

    n = PyParser_SimpleParseFile(fp, r->filename, Py_file_input);

    fclose(fp);

    if (!n)
        return NULL;

    co = (PyObject *)PyNode_Compile(n, r->filename);
    PyNode_Free(n);

    m = PyImport_ExecCodeModuleEx((char *)name, co, r->filename);
    Py_DECREF(co);

    if (m) {
        PyObject *object = NULL;

#if AP_SERVER_MAJORVERSION_NUMBER < 2
        object = PyLong_FromLongLong(r->finfo.st_mtime);
#else
        object = PyLong_FromLongLong(r->finfo.mtime);
#endif
        PyModule_AddObject(m, "__mtime__", object);
    }

    return m;
}

static int wsgi_reload_required(request_rec *r, PyObject *module)
{
    PyObject *dict = NULL;
    PyObject *object = NULL;
    apr_time_t mtime = 0;

    dict = PyModule_GetDict(module);
    object = PyDict_GetItemString(dict, "__mtime__");

    if (object) {
        mtime = PyLong_AsLongLong(object);
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        if (mtime != r->finfo.st_mtime)
            return 1;
#else
        if (mtime != r->finfo.mtime)
            return 1;
#endif
    }
    else
        return 1;

    return 0;
}

static char *wsgi_module_name(request_rec *r)
{
    char *hash = NULL;

    /*
     * Calculate a name for the module using the MD5 of its full
     * pathname. This is so that different code files with the
     * same basename are still considered unique.
     */

    hash = ap_md5(r->pool, (const unsigned char *)r->filename);
    return apr_pstrcat(r->pool, "_mod_wsgi_", hash, NULL);
}

static int wsgi_execute_script(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    InterpreterObject *interp = NULL;
    PyObject *modules = NULL;
    PyObject *module = NULL;
    LogObject *log = NULL;
    char *name = NULL;
    int found = 0;

    int status;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /*
     * Acquire the desired python interpreter. Once this is done
     * it is safe to start manipulating python objects.
     */

    interp = wsgi_acquire_interpreter(config->application_group);

    if (!interp) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
                     "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                     getpid(), config->application_group);
#else
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r,
                     "mod_wsgi (pid=%d): Cannot acquire interpreter '%s'.",
                     getpid(), config->application_group);
#endif

        if (Py_FlushLine())
            PyErr_Clear();

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Calculate the Python module name to be used for script. */

    name = wsgi_module_name(r);

    /*
     * Use a lock around the check to see if the module is
     * already loaded and the import of the module to prevent
     * two request handlers trying to import the module at the
     * same time.
     */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_lock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    modules = PyImport_GetModuleDict();
    module = PyDict_GetItemString(modules, name);

    Py_XINCREF(module);

    if (module)
        found = 1;

    /*
     * If script reloading is enabled and the module exists, see
     * if it has been modified since the last time it was
     * accessed. If it has, interpreter reloading is enabled
     * and it is not the main Python interpreter, we need to
     * trigger destruction of the interpreter by removing it
     * from the interpreters table, releasing it and then
     * reacquiring it. If just script reloading is enabled,
     * remove the module from the modules dictionary before
     * reloading it again. If code is executing within the
     * module at the time, the callers reference count on the
     * module should ensure it isn't actually destroyed until it
     * is finished.
     */

    if (module && config->script_reloading) {
        if (wsgi_reload_required(r, module)) {
            /* Discard reference to loaded module. */

            Py_DECREF(module);
            module = NULL;

            /* Check for interpreter or module reloading. */

            if (config->reload_mechanism == 1 && *config->application_group) {
                /* Remove interpreter from set of interpreters. */

                wsgi_remove_interpreter(config->application_group);

                /*
                 * Release the interpreter. If nothing else is
                 * making use of it, this will cause it to be
                 * destroyed immediately. If something was using
                 * it then it will hang around till the other
                 * handler has finished using it. This will
                 * leave us without even the Python GIL being
                 * locked.
                 */

                wsgi_release_interpreter(interp);

                /*
                 * Now reacquire the interpreter. Because we
                 * removed it from the interpreter set above,
                 * this will result in it being recreated. This
                 * also reacquires the Python GIL for us.
                 */

                interp = wsgi_acquire_interpreter(config->application_group);

                if (!interp) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
                                 "mod_wsgi (pid=%d): Cannot acquire "
                                 "interpreter '%s'.", getpid(),
                                 config->application_group);
#else
                    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r,
                                 "mod_wsgi (pid=%d): Cannot acquire "
                                 "interpreter '%s'.", getpid(),
                                 config->application_group);
#endif

                    if (Py_FlushLine())
                        PyErr_Clear();

#if APR_HAS_THREADS
                    Py_BEGIN_ALLOW_THREADS
                    apr_thread_mutex_unlock(wsgi_module_lock);
                    Py_END_ALLOW_THREADS
#endif

                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                found = 0;
            }
            else
                PyDict_DelItemString(modules, name);
        }
    }

    /* Load module if not already loaded. */

    if (!module)
        module = wsgi_load_source(r, name, found);

    /* Safe now to release the module lock. */

#if APR_HAS_THREADS
    Py_BEGIN_ALLOW_THREADS
    apr_thread_mutex_unlock(wsgi_module_lock);
    Py_END_ALLOW_THREADS
#endif

    /* Assume an internal server error unless everything okay. */

    status = HTTP_INTERNAL_SERVER_ERROR;

    /*
     * Construct a log object to be used for the request or for
     * dumping out any exception details if couldn't load the
     * module or run the script.
     */

    log = newLogObject(r);

    /* Determine if script is executable and execute it. */

    if (module) {
        PyObject *module_dict = NULL;
        PyObject *object = NULL;

        module_dict = PyModule_GetDict(module);
        object = PyDict_GetItemString(module_dict, config->callable_object);

        if (object) {
            AdapterObject *adapter = NULL;
            adapter = newAdapterObject(r, log);

            Py_INCREF(object);

            if (adapter)
                status = Adapter_run(adapter, object);

            Py_XDECREF((PyObject *)adapter);

            Py_DECREF(object);
        }
        else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
                          "mod_wsgi (pid=%d): Target WSGI script '%s' does "
                          "not contain WSGI application '%s'.",
                          getpid(), r->filename, apr_pstrcat(r->pool,
                          r->filename, "::", config->callable_object, NULL));
#else
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r,
                          "mod_wsgi (pid=%d): Target WSGI script '%s' does "
                          "not contain WSGI application '%s'.",
                          getpid(), r->filename, apr_pstrcat(r->pool,
                          r->filename, "::", config->callable_object, NULL));
#endif

            status = HTTP_NOT_FOUND;
        }
    }
    else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, r,
                      "mod_wsgi (pid=%d): Target WSGI script '%s' cannot "
                      "be loaded as Python module.", getpid(), r->filename);
#else
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r,
                      "mod_wsgi (pid=%d): Target WSGI script '%s' cannot "
                      "be loaded as Python module.", getpid(), r->filename);
#endif
    }

    /* Log any details of exceptions if execution failed. */

    if (PyErr_Occurred()) {
        PyObject *m = NULL;
        PyObject *result = NULL;

        PyObject *type = NULL;
        PyObject *value = NULL;
        PyObject *traceback = NULL;

        if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                         r, "mod_wsgi (pid=%d): SystemExit "
                         "exception raised by WSGI script "
                         "'%s' ignored.", getpid(), r->filename);
#else
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                         0, r, "mod_wsgi (pid=%d): SystemExit "
                         "exception raised by WSGI script "
                         "'%s' ignored.", getpid(), r->filename);
#endif
        }
        else {
#if AP_SERVER_MAJORVERSION_NUMBER < 2
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                         r, "mod_wsgi (pid=%d): Exception "
                         "occurred within WSGI script '%s'.",
                         getpid(), r->filename);
#else
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE,
                         0, r, "mod_wsgi (pid=%d): Exception "
                         "occurred within WSGI script '%s'.",
                         getpid(), r->filename);
#endif
        }

        PyErr_Fetch(&type, &value, &traceback);

        if (!value) {
            value = Py_None;
            Py_INCREF(value);
        }

        if (!traceback) {
            traceback = Py_None;
            Py_INCREF(traceback);
        }

        m = PyImport_ImportModule("traceback");

        if (m) {
            PyObject *d = NULL;
            PyObject *o = NULL;
            d = PyModule_GetDict(m);
            o = PyDict_GetItemString(d, "print_exception");
            if (o) {
                PyObject *args = NULL;
                Py_INCREF(o);
                args = Py_BuildValue("(OOOOO)", type, value, traceback,
                                     Py_None, log);
                result = PyEval_CallObject(o, args);
                Py_DECREF(args);
            }
            Py_DECREF(o);
        }

        if (!result) {
            /*
             * If can't output exception and traceback then
             * use PyErr_Print to dump out details of the
             * exception. For SystemExit though if we do
             * that the process will actually be terminated
             * so can only clear the exception information
             * and keep going.
             */

            PyErr_Restore(type, value, traceback);

            if (!PyErr_ExceptionMatches(PyExc_SystemExit)) {
                PyErr_Print();
                if (Py_FlushLine())
                    PyErr_Clear();
            }
            else {
                PyErr_Clear();
            }
        }
        else {
            Py_XDECREF(type);
            Py_XDECREF(value);
            Py_XDECREF(traceback);
        }

        Py_XDECREF(result);

        Py_DECREF(m);
    }

    Py_XDECREF(module);

    Py_DECREF(log);

    wsgi_release_interpreter(interp);

    return status;
}

/*
 * Apache child process initialision and cleanup. Initialise
 * global table containing Python interpreter instances and
 * cache reference to main interpreter. Also register cleanup
 * function to delete interpreter on process shutdown.
 */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
static void wsgi_python_child_cleanup(void *data)
#else
static apr_status_t wsgi_python_child_cleanup(void *data)
#endif
{
    PyObject *interp = NULL;

    /* In a multithreaded MPM must protect table. */

#if APR_HAS_THREADS
    apr_thread_mutex_lock(wsgi_interp_lock);
#endif

    PyEval_AcquireLock();

    /*
     * Extract a handle to the main Python interpreter from
     * interpreters dictionary as want to process that one last.
     */

    interp = PyDict_GetItemString(wsgi_interpreters, "");
    Py_INCREF(interp);

    /*
     * Remove all items from interpreters dictionary. This will
     * have side affect of calling any exit functions and
     * destroying interpreters we own.
     */

    PyDict_Clear(wsgi_interpreters);

#if APR_HAS_THREADS
    apr_thread_mutex_unlock(wsgi_interp_lock);
#endif

    /*
     * Now we decrement reference on handle for main Python
     * interpreter. This only causes exit functions to be called
     * and doesn't result in interpreter being destroyed as we
     * we didn't previously mark ourselves as the owner of the
     * interpreter. Note that when Python as a whole is later
     * being destroyed it will also call exit functions, but by
     * then the exit function registrations have been removed
     * and so they will not actually be run a second time.
     */

    Py_DECREF(interp);

    PyEval_ReleaseLock();

    /*
     * Destroy Python itself including the main interpreter.
     * If mod_python is being loaded it is left to mod_python to
     * destroy mod_python, although it currently doesn't do so.
     */

    if (wsgi_python_initialized)
        wsgi_python_term(0);

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    return APR_SUCCESS;
#endif
}

static void wsgi_python_child_init(apr_pool_t *p)
{
    PyInterpreterState *interp = NULL;
    PyThreadState *tstate = NULL;
    PyThreadState *save_tstate = NULL;

    PyObject *object = NULL;

    /* Working with Python, so must acquire GIL. */

    PyEval_AcquireLock();

    /*
     * Get a reference to the main Python interpreter created
     * and associate our own thread state against it.
     */

    interp = PyInterpreterState_Head();
    while (interp->next)
        interp = interp->next;

    tstate = PyThreadState_New(interp);
    save_tstate = PyThreadState_Swap(tstate);

    /*
     * Trigger any special Python stuff required after a fork.
     * Only do this though if we were responsible for the
     * initialisation of the Python interpreter in the first
     * place to avoid it being done multiple times.
     */

    if (wsgi_python_initialized)
        PyOS_AfterFork();

    /* Finalise any Python objects required by child process. */

    PyType_Ready(&Log_Type);
    PyType_Ready(&Input_Type);
    PyType_Ready(&Adapter_Type);
    PyType_Ready(&Restricted_Type);
    PyType_Ready(&Interpreter_Type);

    /* Initialise Python interpreter instance table and lock. */

    wsgi_interpreters = PyDict_New();

#if APR_HAS_THREADS
    apr_thread_mutex_create(&wsgi_interp_lock, APR_THREAD_MUTEX_UNNESTED, p);
    apr_thread_mutex_create(&wsgi_module_lock, APR_THREAD_MUTEX_UNNESTED, p);
#endif

    /*
     * Cache a reference to the first Python interpreter
     * instance. This interpreter is special as some third party
     * Python modules will only work when used from within this
     * interpreter. This is generally when they use the Python
     * simplified GIL API or otherwise don't use threading API
     * properly.
     */

    object = (PyObject *)newInterpreterObject("", interp);
    PyDict_SetItemString(wsgi_interpreters, "", object);
    Py_DECREF(object);

    /* Restore the prior thread state and release the GIL. */

    PyThreadState_Clear(tstate);
    PyThreadState_Swap(save_tstate);
    PyThreadState_Delete(tstate);

    PyEval_ReleaseLock();

    /* Register cleanups to performed on process shutdown. */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    ap_register_cleanup(p, NULL, wsgi_python_child_cleanup,
                        ap_null_cleanup);
#else
    apr_pool_cleanup_register(p, NULL, wsgi_python_child_cleanup,
                              apr_pool_cleanup_null);
#endif
}

/* The processors for directives. */

static const char *wsgi_add_script_alias(cmd_parms *cmd, void *mconfig,
                                         const char *l, const char *a)
{
    WSGIServerConfig *config = NULL;
    WSGIAliasEntry *entry = NULL;

    config = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (!config->alias_list) {
        config->alias_list = apr_array_make(config->pool, 20,
                                            sizeof(WSGIAliasEntry));
    }

    entry = (WSGIAliasEntry *)apr_array_push(config->alias_list);

    if (cmd->info) {
        entry->regexp = ap_pregcomp(cmd->pool, l, AP_REG_EXTENDED);
        if (!entry->regexp)
            return "Regular expression could not be compiled.";
    }

    entry->location = l;
    entry->application = a;

    return NULL;
}

static const char *wsgi_set_python_optimize(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->python_optimize = !strcasecmp(f, "On");

    return NULL;
}

static const char *wsgi_set_restrict_stdin(cmd_parms *cmd, void *mconfig,
                                           const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->restrict_stdin = !!strcasecmp(f, "Off");

    return NULL;
}

static const char *wsgi_set_restrict_stdout(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->restrict_stdout = !!strcasecmp(f, "Off");

    return NULL;
}

static const char *wsgi_set_restrict_signal(cmd_parms *cmd, void *mconfig,
                                            const char *f)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);
    sconfig->restrict_signal = !!strcasecmp(f, "Off");

    return NULL;
}

static const char *wsgi_set_process_name(cmd_parms *cmd, void *mconfig,
                                         const char *n)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->process_name = n;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->process_name = n;
    }

    return NULL;
}

static const char *wsgi_set_application_group(cmd_parms *cmd, void *mconfig,
                                              const char *n)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->application_group = n;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->application_group = n;
    }

    return NULL;
}

static const char *wsgi_set_callable_object(cmd_parms *cmd, void *mconfig,
                                            const char *n)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->callable_object = n;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->callable_object = n;
    }

    return NULL;
}

static const char *wsgi_set_pass_authorization(cmd_parms *cmd, void *mconfig,
                                               const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->pass_authorization = !strcasecmp(f, "On");
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->pass_authorization = !strcasecmp(f, "On");
    }

    return NULL;
}

static const char *wsgi_set_script_reloading(cmd_parms *cmd, void *mconfig,
                                             const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->script_reloading = !strcasecmp(f, "On");
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->script_reloading = !strcasecmp(f, "On");
    }

    return NULL;
}

static const char *wsgi_set_reload_mechanism(cmd_parms *cmd, void *mconfig,
                                             const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        if (!strcasecmp(f, "Interpreter"))
            dconfig->reload_mechanism = 1;
        else
            dconfig->reload_mechanism = 0;
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        if (!strcasecmp(f, "Interpreter"))
            sconfig->reload_mechanism = 1;
        else
            sconfig->reload_mechanism = 0;
    }

    return NULL;
}

static const char *wsgi_set_output_buffering(cmd_parms *cmd, void *mconfig,
                                             const char *f)
{
    if (cmd->path) {
        WSGIDirectoryConfig *dconfig = NULL;
        dconfig = (WSGIDirectoryConfig *)mconfig;
        dconfig->output_buffering = !strcasecmp(f, "On");
    }
    else {
        WSGIServerConfig *sconfig = NULL;
        sconfig = ap_get_module_config(cmd->server->module_config,
                                       &wsgi_module);
        sconfig->output_buffering = !strcasecmp(f, "On");
    }

    return NULL;
}

/* Handler for the translate name phase. */

static int wsgi_alias_matches(const char *uri, const char *alias_fakename)
{
    /* Code for this function from Apache mod_alias module. */

    const char *aliasp = alias_fakename, *urip = uri;

    while (*aliasp) {
        if (*aliasp == '/') {
            /* any number of '/' in the alias matches any number in
             * the supplied URI, but there must be at least one...
             */
            if (*urip != '/')
                return 0;

            do {
                ++aliasp;
            } while (*aliasp == '/');
            do {
                ++urip;
            } while (*urip == '/');
        }
        else {
            /* Other characters are compared literally */
            if (*urip++ != *aliasp++)
                return 0;
        }
    }

    /* Check last alias path component matched all the way */

    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;

    /* Return number of characters from URI which matched (may be
     * greater than length of alias, since we may have matched
     * doubled slashes)
     */

    return urip - uri;
}

static int wsgi_hook_intercept(request_rec *r)
{
    WSGIServerConfig *config = NULL;

    apr_array_header_t *aliases = NULL;

    WSGIAliasEntry *entries = NULL;
    WSGIAliasEntry *entry = NULL;

    ap_regmatch_t matches[AP_MAX_REG_MATCH];

    const char *location = NULL;
    const char *application = NULL;

    int i = 0;

    config = ap_get_module_config(r->server->module_config, &wsgi_module);

    if (!config->alias_list)
        return DECLINED;

    if (r->uri[0] != '/' && r->uri[0])
        return DECLINED;

    aliases = config->alias_list;
    entries = (WSGIAliasEntry *)aliases->elts;

    for (i = 0; i < aliases->nelts; ++i) {
        int l = 0;

        entry = &entries[i];

        if (entry->regexp) {
            if (!ap_regexec(entry->regexp, r->uri, AP_MAX_REG_MATCH,
                matches, 0)) {
                if (entry->application) {
                    l = matches[0].rm_eo;

                    location = apr_pstrndup(r->pool, r->uri, l);
                    application = ap_pregsub(r->pool, entry->application,
                                             r->uri, AP_MAX_REG_MATCH,
                                             matches);
                }
            }
        }
        else if (entry->location) {
            l = wsgi_alias_matches(r->uri, entry->location);

            location = entry->location;
            application = entry->application;
        }

        if (l > 0) {
            if (!strcmp(location, "/")) {
                r->filename = apr_pstrcat(r->pool, application,
                                          r->uri, NULL);
            }
            else {
                r->filename = apr_pstrcat(r->pool, application,
                                          r->uri + l, NULL);
            }

            r->handler = "wsgi-script";
            apr_table_setn(r->notes, "alias-forced-type", r->handler);

            return OK;
        }
    }

    return DECLINED;
}

/* Handler for the response handler phase. */

static void wsgi_log_script_error(request_rec *r, const char *e, const char *n)
{
    char *message = NULL;

    if (!n)
        n = r->filename;

    message = apr_psprintf(r->pool, "%s: %s", e, n);
    apr_table_set(r->notes, "error-notes", message);

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, message);
#else
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, message);
#endif
}

static void wsgi_build_environment(request_rec *r)
{
    WSGIRequestConfig *config = NULL;

    const char *value = NULL;
    const char *script_name = NULL;
    const char *path_info = NULL;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /* Populate environment with standard CGI variables. */

    ap_add_cgi_vars(r);
    ap_add_common_vars(r);

    /* Determine whether connection uses HTTPS protocol. */

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    if (!wsgi_is_https)
        wsgi_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    if (wsgi_is_https && wsgi_is_https(r->connection))
        apr_table_set(r->subprocess_env, "HTTPS", "1");
#endif

    /*
     * If enabled, pass along authorisation headers which Apache
     * leaves out of CGI environment. WSGI still needs to see
     * these if it needs to implement any of the standard
     * authentication schemes such as Basic and Digest. We do
     * not pass these through by default though as it can result
     * in passwords being leaked though to a WSGI application
     * when it shouldn't. This would be a problem where there is
     * some sort of site wide authorisation scheme in place
     * which has got nothing to do with specific applications.
     */

    if (config->pass_authorization) {
        value = apr_table_get(r->headers_in, "Authorization");
        if (value)
            apr_table_setn(r->subprocess_env, "HTTP_AUTHORIZATION", value);

        value = apr_table_get(r->headers_in, "Proxy-Authorization");
        if (value)
            apr_table_setn(r->subprocess_env, "HTTP_PROXY_AUTHORIZATION",
                           value);
    }

    /* If PATH_INFO not set, set it to an empty string. */

    value = apr_table_get(r->subprocess_env, "PATH_INFO");
    if (!value)
        apr_table_setn(r->subprocess_env, "PATH_INFO", "");

    /*
     * Multiple slashes are not always collapsed into a single
     * slash in SCRIPT_NAME and PATH_INFO with Apache 1.3 and
     * Apache 2.X behaving a bit differently. Because some WSGI
     * applications don't deal with multiple slashes properly we
     * collapse any duplicate slashes to a single slash so
     * Apache behaviour is consistent across all versions. We
     * don't care that PATH_TRANSLATED can on Apache 1.3 still
     * contain multiple slashes as that should not be getting
     * used from a WSGI application anyway.
     */

    script_name = apr_table_get(r->subprocess_env, "SCRIPT_NAME");

    if (*script_name) {
        while (*script_name && (*(script_name+1) == '/'))
            script_name++;
        script_name = apr_pstrdup(r->pool, script_name);
        ap_no2slash((char*)script_name);
        apr_table_setn(r->subprocess_env, "SCRIPT_NAME", script_name);
    }

    path_info = apr_table_get(r->subprocess_env, "PATH_INFO");

    if (*path_info) {
        while (*path_info && (*(path_info+1) == '/'))
            path_info++;
        path_info = apr_pstrdup(r->pool, path_info);
        ap_no2slash((char*)path_info);
        apr_table_setn(r->subprocess_env, "PATH_INFO", path_info);
    }
}

static int wsgi_is_script_aliased(request_rec *r)
{
    const char *t = NULL;

    t = apr_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "wsgi-script"));
}

#if !defined(WIN32)
#if AP_SERVER_MAJORVERSION_NUMBER >= 2
static int wsgi_execute_remote(request_rec *r);
#endif
#endif

static int wsgi_hook_handler(request_rec *r)
{
    int status;

    WSGIRequestConfig *config = NULL;

    /*
     * Only process requests for this module. Honour a content
     * type here because mod_rewrite prior to Apache 2.2 only
     * provides a means of setting content type and doesn't
     * provide a means of setting the handler name explicitly.
     */

    if (!r->handler || (strcmp(r->handler, "wsgi-script") &&
        strcmp(r->handler, "application/x-httpd-wsgi"))) {
        return DECLINED;
    }

    /*
     * Ensure that have adequate privileges to run the WSGI
     * script. Require ExecCGI to be specified in Options for
     * this. In doing this, using the wider interpretation that
     * ExecCGI refers to any executable like script even though
     * not a separate process execution.
     */

    if (!(ap_allow_options(r) & OPT_EXECCGI) && !wsgi_is_script_aliased(r)) {
        wsgi_log_script_error(r, "Options ExecCGI is off in this directory",
                              r->filename);
        return HTTP_FORBIDDEN;
    }

    /* Ensure target script exists and is a file. */

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    if (r->finfo.st_mode == 0) {
        wsgi_log_script_error(r, "Target WSGI script not found or unable "
                              "to stat", r->filename);
        return HTTP_NOT_FOUND;
    }
#else
    if (r->finfo.filetype == 0) {
        wsgi_log_script_error(r, "Target WSGI script not found or unable "
                              "to stat", r->filename);
        return HTTP_NOT_FOUND;
    }
#endif

#if AP_SERVER_MAJORVERSION_NUMBER < 2
    if (S_ISDIR(r->finfo.st_mode)) {
        wsgi_log_script_error(r, "Attempt to invoke directory as WSGI "
                              "application", r->filename);
        return HTTP_FORBIDDEN;
    }
#else
    if (r->finfo.filetype == APR_DIR) {
        wsgi_log_script_error(r, "Attempt to invoke directory as WSGI "
                              "application", r->filename);
        return HTTP_FORBIDDEN;
    }
#endif

    /*
     * For Apache 2.0+ honour AcceptPathInfo directive. Default
     * behaviour is accept additional path information. Under
     * Apache 1.3, WSGI application would need to check itself.
     */

#if AP_MODULE_MAGIC_AT_LEAST(20011212,0)
    if ((r->used_path_info == AP_REQ_REJECT_PATH_INFO) &&
        r->path_info && *r->path_info) {
        wsgi_log_script_error(r, "AcceptPathInfo off disallows user's path",
                              r->filename);
        return HTTP_NOT_FOUND;
    }
#endif

    /*
     * Setup policy to apply if request contains a body. Note
     * that it is not possible to have chunked transfer encoding
     * for the request content. This is actually a limitation in
     * WSGI specification as it has no way of indicating that
     * there is content of unknown length, nor a way to deal
     * with trailers appearing after any chunked content.
     */

    status = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);

    if (status != OK)
        return status;

    /*
     * Construct request configuration and cache it in the
     * request object against this module so can access it
     * later from handler code.
     */

    config = wsgi_create_req_config(r->pool, r);

    ap_set_module_config(r->request_config, &wsgi_module, config);

    /* Build the sub process environment. */

    wsgi_build_environment(r);

    /*
     * Execute the target WSGI application script or proxy
     * request to one of the daemon processes as appropriate.
     */

#if AP_SERVER_MAJORVERSION_NUMBER >= 2
    if (*config->process_name)
        return wsgi_execute_remote(r);
#endif

    return wsgi_execute_script(r);
}

#if AP_SERVER_MAJORVERSION_NUMBER < 2

/*
 * Apache 1.3 module initialisation functions.
 */

void wsgi_hook_init(server_rec *s, apr_pool_t *p)
{
    char package[128];

    /* Setup module version information. */

    sprintf(package, "mod_wsgi/%d.%d-TRUNK", MOD_WSGI_MAJORVERSION_NUMBER,
            MOD_WSGI_MINORVERSION_NUMBER);

    ap_add_version_component(package);

    /* Retain reference to main server config. */

    wsgi_server_config = ap_get_module_config(s->module_config, &wsgi_module);

    /* Initialise Python if not already done. */

    wsgi_python_init(NULL);
}

static void wsgi_hook_child_init(server_rec *s, apr_pool_t *p)
{
    wsgi_python_child_init(p);
}

/* Dispatch list of content handlers */
static const handler_rec wsgi_handlers[] = {
    { "wsgi-script", wsgi_hook_handler },
    { "application/x-httpd-wsgi", wsgi_hook_handler },
    { NULL, NULL }
};

static const command_rec wsgi_commands[] =
{
    { "WSGIScriptAlias", wsgi_add_script_alias, NULL,
        RSRC_CONF, TAKE2, "Map location to target WSGI script file." },
    { "WSGIScriptAliasMatch", wsgi_add_script_alias, "*",
        RSRC_CONF, TAKE2, "Map location to target WSGI script file." },

    { "WSGIPythonOptimize", wsgi_set_python_optimize, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable Python compiler optimisations." },
    { "WSGIRestrictStdin", wsgi_set_restrict_stdin, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable restrictions on use of STDIN." },
    { "WSGIRestrictStdout", wsgi_set_restrict_stdout, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable restrictions on use of STDOUT." },
    { "WSGIRestrictSignal", wsgi_set_restrict_signal, NULL,
        RSRC_CONF, TAKE1, "Enable/Disable restrictions on use of signal()." },

    { "WSGIApplicationGroup", wsgi_set_application_group, NULL,
        OR_FILEINFO, TAKE1, "Name of the WSGI application group to use." },
    { "WSGICallableObject", wsgi_set_callable_object, NULL,
        OR_FILEINFO, TAKE1, "Name of entry point in WSGI script file." },

    { "WSGIPassAuthorization", wsgi_set_pass_authorization, NULL,
        OR_FILEINFO, TAKE1, "Enable/Disable passing authorization headers." },
    { "WSGIScriptReloading", wsgi_set_script_reloading, NULL,
        OR_FILEINFO, TAKE1, "Enable/Disable script reloading mechanism." },
    { "WSGIReloadMechanism", wsgi_set_reload_mechanism, NULL,
        OR_FILEINFO, TAKE1, "Defines what is reloaded when a reload occurs." },
    { "WSGIOutputBuffering", wsgi_set_output_buffering, NULL,
        OR_FILEINFO, TAKE1, "Enable/Disable buffering of response." },

    { NULL }
};

/* Dispatch list for API hooks */

module MODULE_VAR_EXPORT wsgi_module = {
    STANDARD_MODULE_STUFF,
    wsgi_hook_init,            /* module initializer                  */
    wsgi_create_dir_config,    /* create per-dir    config structures */
    wsgi_merge_dir_config,     /* merge  per-dir    config structures */
    wsgi_create_server_config, /* create per-server config structures */
    wsgi_merge_server_config,  /* merge  per-server config structures */
    wsgi_commands,             /* table of config file commands       */
    wsgi_handlers,             /* [#8] MIME-typed-dispatched handlers */
    wsgi_hook_intercept,       /* [#1] URI to filename translation    */
    NULL,                      /* [#4] validate user id from request  */
    NULL,                      /* [#5] check if the user is ok _here_ */
    NULL,                      /* [#3] check access by host address   */
    NULL,                      /* [#6] determine MIME type            */
    NULL,                      /* [#7] pre-run fixups                 */
    NULL,                      /* [#9] log a transaction              */
    NULL,                      /* [#2] header parser                  */
    wsgi_hook_child_init,      /* child_init                          */
    NULL,                      /* child_exit                          */
    NULL                       /* [#0] post read-request              */
#ifdef EAPI
   ,NULL,                      /* EAPI: add_module                    */
    NULL,                      /* EAPI: remove_module                 */
    NULL,                      /* EAPI: rewrite_command               */
    NULL                       /* EAPI: new_connection                */
#endif
};

#else

/*
 * Apache 2.X and UNIX specific code for creation and management
 * of distinct daemon processes.
 */

#if !defined(WIN32)

#include "unixd.h"

#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <sys/un.h>

#ifndef WSGI_LISTEN_BACKLOG
#define WSGI_LISTEN_BACKLOG 100
#endif

#ifndef WSGI_CONNECT_ATTEMPTS
#define WSGI_CONNECT_ATTEMPTS 15
#endif

typedef struct {
    server_rec *server;
    int count;
    const char *name;
    const char *user;
    uid_t uid;
    const char *group;
    gid_t gid;
    apr_proc_t process;
    pid_t pid;
    const char *socket;
} WSGIDaemonEntry;

typedef struct {
    const char *name;
    const char *path;
    int fd;
} WSGIDaemonSocket;

static apr_pool_t *wsgi_parent_pool = NULL;
static apr_pool_t *wsgi_daemon_pool = NULL;

static int wsgi_daemon_count = 0;
static apr_table_t *wsgi_daemon_sockets = NULL;

static int wsgi_daemon_shutdown = 0;

static const char *wsgi_add_daemon_process(cmd_parms *cmd, void *mconfig,
                                         const char *args)
{
    const char *error = NULL;
    WSGIServerConfig *config = NULL;

    const char *name = NULL;
    const char *user = NULL;
    const char *group = NULL;

    uid_t uid = unixd_config.user_id;
    uid_t gid = unixd_config.group_id;

    const char *option = NULL;
    const char *value = NULL;

    apr_array_header_t *daemons = NULL;

    WSGIDaemonEntry *entries = NULL;
    WSGIDaemonEntry *entry = NULL;

    int i;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    name = ap_getword_conf(cmd->temp_pool, &args);

    if (!name || !*name)
        return "Name of WSGI daemon process not supplied.";

    while (*args) {
        option = ap_getword_conf(cmd->temp_pool, &args);

        if (strstr(option, "user=") == option) {
            value = option + 5;
            if (!*value)
                return "Invalid user for WSGI daemon process.";

            user = value;
            uid = ap_uname2id(user);
            if (uid == 0)
                return "WSGI process blocked from running as root.";

            if (*user == '#') {
                struct passwd *entry = NULL;

                if ((entry = getpwuid(uid)) == NULL)
                    return "Couldn't determine user name from uid.";

                user = entry->pw_name;
            }
        }
        else if (strstr(option, "group=") == option) {
            value = option + 6;
            if (!*value)
                return "Invalid group for WSGI daemon process.";

            group = value;
            gid = ap_gname2id(group);
        }
        else
            return "Invalid option to WSGI daemon process definition.";
    }

    config = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    if (!config->daemon_list) {
        config->daemon_list = apr_array_make(config->pool, 20,
                                             sizeof(WSGIDaemonEntry));
    }

    daemons = config->daemon_list;
    entries = (WSGIDaemonEntry *)daemons->elts;

    for (i = 0; i < daemons->nelts; ++i) {
        entry = &entries[i];

        if (!strcmp(entry->name, name))
            return "Name duplicates previous WSGI daemon definition.";
    }

    entry = (WSGIDaemonEntry *)apr_array_push(config->daemon_list);

    entry->server = cmd->server;

    entry->count = ++wsgi_daemon_count;

    entry->name = apr_pstrdup(config->pool, name);
    entry->user = apr_pstrdup(config->pool, user);
    entry->group = apr_pstrdup(config->pool, group);

    entry->uid = uid;
    entry->gid = gid;

    return NULL;
}

static const char *wsgi_set_socket_prefix(cmd_parms *cmd, void *mconfig,
                                         const char *arg)
{
    const char *error = NULL;
    WSGIServerConfig *sconfig = NULL;

    error = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (error != NULL)
        return error;

    sconfig = ap_get_module_config(cmd->server->module_config, &wsgi_module);

    sconfig->socket_prefix = apr_psprintf(cmd->pool, "%s.%d", arg, getpid());
    sconfig->socket_prefix = ap_server_root_relative(cmd->pool,
                                                     sconfig->socket_prefix);

    if (!sconfig->socket_prefix) {
        return apr_pstrcat(cmd->pool, "Invalid WSGISocketPrefix '",
                           arg, "'.", NULL);
    }

    return NULL;
}

static void wsgi_signal_handler(int sig)
{
    if (sig == SIGHUP)
        wsgi_daemon_shutdown++;
}

#if APR_HAS_OTHER_CHILD
static int wsgi_start_process(apr_pool_t *p, WSGIDaemonEntry *daemon);

static void wsgi_manage_process(int reason, void *data, apr_wait_t status)
{
    WSGIDaemonEntry *daemon = data;

    switch (reason) {

        /* Child daemon process has died. */

        case APR_OC_REASON_DEATH: {
            int mpm_state;
            int stopping;

            /* Stop watching the existing process. */

            apr_proc_other_child_unregister(daemon);

            /*
             * Determine if Apache is being shutdown or not and
             * if it is not being shutdown, restart the child
             * daemon process that has died. If MPM doesn't
             * support query assume that child daemon process
             * shouldn't be restarted.
             */

            stopping = 1;

            if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state) == APR_SUCCESS
                && mpm_state != AP_MPMQ_STOPPING) {
                stopping = 0;
            }

            if (!stopping) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, daemon->server,
                             "mod_wsgi: Child daemon process '%s' died, "
                             "restarting.", daemon->name);
                wsgi_start_process(wsgi_parent_pool, daemon);
            }

            break;
        }

        /* Apache is being restarted. */

        case APR_OC_REASON_RESTART: {
            /*
             * Any child daemon processed will be killed off
             * automatically so just need to stop watching the
             * existing process.
             */

            apr_proc_other_child_unregister(daemon);

            break;
        }

        /* Child daemon process vanished. */

        case APR_OC_REASON_LOST: {
            /*
             * Stop watching the existing process and then
             * restart the child daemon process that has died.
             */

            apr_proc_other_child_unregister(daemon);

            ap_log_error(APLOG_MARK, APLOG_ERR, 0, daemon->server,
                         "mod_wsgi: Child daemon process '%s' died, "
                         "restarting.", daemon->name);
            wsgi_start_process(wsgi_parent_pool, daemon);

            break;
        }

        /* Call to unregister the process. */

        case APR_OC_REASON_UNREGISTER: {
            /* Send signal to kill child daemon process. */

            kill(daemon->process.pid, SIGHUP);

            /* Remove socket used for communicating with daemon. */

            if (unlink(daemon->socket) < 0 && errno != ENOENT) {
                ap_log_error(APLOG_MARK, APLOG_ERR, errno, daemon->server,
                             "mod_wsgi (pid=%d): Couldn't unlink unix domain "
                             "socket '%s'.", getpid(), daemon->socket);
            }

            break;
        }
    }
}
#endif

static void wsgi_setup_access(WSGIDaemonEntry *daemon)
{
    /* Don't bother switch user/group if not root. */

    if (geteuid())
        return;

    /* Setup the daemon process real and effective group. */

    if (setgid(daemon->gid) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, daemon->server,
                     "mod_wsgi (pid=%d): Unable to set group id to gid=%d.",
                     getpid(), daemon->gid);
    }
    else {
        if (initgroups(daemon->name, daemon->gid) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, daemon->server,
                        "mod_wsgi (pid=%d): Unable to set groups for uname=%s "
                        "and gid=%u.", getpid(), daemon->name,
                        (unsigned)daemon->gid);
        }
    }

    /* Setup the daemon process real and effective user. */

    if (setuid(daemon->uid) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, errno, daemon->server,
                     "mod_wsgi (pid=%d): Unable to change to uid=%ld.",
                     getpid(), (long)daemon->uid);
    }
}

static int wsgi_setup_socket(WSGIDaemonEntry *daemon)
{
    int sockfd = -1;
    struct sockaddr_un addr;
    apr_socklen_t addlen;
    mode_t omask;
    int rc;

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, daemon->server,
                 "mod_wsgi (pid=%d): Socket for '%s' is '%s'.",
                 getpid(), daemon->name, daemon->socket);

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, daemon->server,
                     "mod_wsgi (pid=%d): Couldn't create unix domain "
                     "socket.", getpid());
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, daemon->socket, sizeof(addr.sun_path));

    omask = umask(0077);
    rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    umask(omask);
    if (rc < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, daemon->server,
                     "mod_wsgi (pid=%d): Couldn't bind unix domain "
                     "socket '%s'.", getpid(), daemon->socket);
        return -1;
    }

    if (listen(sockfd, WSGI_LISTEN_BACKLOG) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, daemon->server,
                     "mod_wsgi (pid=%d): Couldn't listen on unix domain "
                     "socket.", getpid());
        return -1;
    }

    if (!geteuid()) {
        if (chown(daemon->socket, unixd_config.user_id, -1) < 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, errno, daemon->server,
                         "mod_wsgi (pid=%d): Couldn't change owner of unix "
                         "domain socket '%s'.", getpid(), daemon->socket);
            return errno;
        }
    }

    return sockfd;
}

static void wsgi_daemon_main(WSGIDaemonEntry *daemon, int sockfd)
{
    /*
     * When listener socket cannot be created or setup doen't
     * work, dont want to just exit the process as that will
     * create a fork bomb with the parent process continually
     * trying to restart it. Instead just go into a continual
     * sleep loop looking for a signal from parent process to
     * shutdown the process.
     */

    if (sockfd == -1) {
        while (!wsgi_daemon_shutdown)
            sleep(1);

        return;
    }

    while (!wsgi_daemon_shutdown)
        sleep(1);
}

static int wsgi_start_process(apr_pool_t *p, WSGIDaemonEntry *daemon)
{
    if ((daemon->pid = fork()) < 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, daemon->server,
                     "mod_wsgi: Couldn't spawn daemon process '%s'.",
                     daemon->name);
        return DECLINED;
    }
    else if (daemon->pid == 0) {
        int sockfd = -1;

        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, daemon->server,
                     "mod_wsgi (pid=%d): Starting process '%s' with uid=%ld "
                     "and gid=%u.", getpid(), daemon->name, (long)daemon->uid,
                     (unsigned)daemon->gid);

        /*
         * Close child copy of the listening sockets for the
         * Apache parent process so we don't interfere with
         * the parent process.
         */

        ap_close_listeners();

        /*
         * Create a pool for the child daemon process so
         * we can trigger various events off it at shutdown.
         */

        apr_pool_create(&wsgi_daemon_pool, p);

        /*
         * Setup Python in the child daemon process. Note that
         * we ensure that we are marked as the original
         * initialiser of the Python interpreter even though
         * mod_python might have done it, as we will be the one
         * to cleanup the child daemon process and not
         * mod_python. We also need to perform the special
         * Python setup which has to be done after a fork.
         */

        wsgi_python_initialized = 1;
        wsgi_python_child_init(wsgi_daemon_pool);

        /*
         * Register signal handler to receive shutdown signal
         * from Apache parent process.
         */

        wsgi_daemon_shutdown = 0;

        apr_signal(SIGCHLD, SIG_IGN);
        apr_signal(SIGHUP, wsgi_signal_handler);

        /* Create a listener socket for receiving requests. */

        sockfd = wsgi_setup_socket(daemon);

        /* Setup daemon process user/group access. */

        wsgi_setup_access(daemon);

        /* Run the main routine for the daemon process. */

        wsgi_daemon_main(daemon, sockfd);

        /*
         * Destroy the pool for the daemon process. This will
         * have the side affect of also destroying Python.
         */

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, daemon->server,
                     "mod_wsgi (pid=%d): Stopping process '%s'.",
                     getpid(), daemon->name);

        apr_pool_destroy(wsgi_daemon_pool);

        /* Exit the daemon process when being shutdown. */

        exit(-1);
    }

    daemon->process.pid = daemon->pid;
    daemon->process.err = daemon->process.in = daemon->process.out = NULL;
    apr_pool_note_subprocess(p, &daemon->process, APR_KILL_AFTER_TIMEOUT);
#if APR_HAS_OTHER_CHILD
    apr_proc_other_child_register(&daemon->process, wsgi_manage_process,
                                  daemon, NULL, p);
#endif

    return OK;
}

static int wsgi_start_daemons(apr_pool_t *p)
{
    apr_array_header_t *daemons = NULL;

    WSGIDaemonEntry *entries = NULL;
    WSGIDaemonEntry *entry = NULL;

    int i;

    /* Do we need to create any daemon processes. */

    daemons = wsgi_server_config->daemon_list;

    if (!daemons)
        return OK;

    /*
     * Cache references to root server and pool as will need
     * to access these when restarting daemon process when
     * they die.
     */

    wsgi_parent_pool = p;

    /* Startup in turn each of the named daemon process. */

    wsgi_daemon_sockets = apr_table_make(p, wsgi_daemon_count);

    entries = (WSGIDaemonEntry *)daemons->elts;

    for (i = 0; i < daemons->nelts; ++i) {
        int status;

        entry = &entries[i];

        entry->socket = apr_psprintf(p, "%s.%d",
                                     wsgi_server_config->socket_prefix,
                                     entry->count);

        apr_table_setn(wsgi_daemon_sockets, entry->name, entry->socket);

        status = wsgi_start_process(p, entry);

        if (status != OK)
            return status;
    }

    return OK;
}

static apr_status_t wsgi_close_socket(void *data)
{
    WSGIDaemonSocket *daemon = NULL;

    daemon = (WSGIDaemonSocket *)data;

    return close(daemon->fd);
}

static int wsgi_connect_daemon(request_rec *r, WSGIDaemonSocket *daemon)
{
    struct sockaddr_un addr;

    int retries = 0;
    apr_interval_time_t timer = 100000;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    apr_cpystrn(addr.sun_path, daemon->path, sizeof addr.sun_path);

    while (1) {
        retries++;

        if ((daemon->fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, errno, r,
                         "mod_wsgi (pid=%d): Unable to create socket to "
                         "connect to WSGI daemon process.", getpid());

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (connect(daemon->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            if (errno == ECONNREFUSED && retries < WSGI_CONNECT_ATTEMPTS) {
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, errno, r,
                             "mod_wsgi (pid=%d): Connection attempt #%d to "
                             "WSGI daemon process '%s' on '%s' failed, "
                             "sleeping before retrying again.", getpid(),
                             retries, daemon->name, daemon->path);

                close(daemon->fd);

                /* Increase wait time up to maximum of 2 seconds. */

                apr_sleep(timer);
                if (timer < apr_time_from_sec(2))
                    timer *= 2;
            }
            else {
                close(daemon->fd);

                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, errno, r,
                             "mod_wsgi (pid=%d): Unable to connect to "
                             "WSGI daemon process '%s' on '%s' after "
                             "multiple attempts.", getpid(), daemon->name,
                             daemon->path);

                return HTTP_SERVICE_UNAVAILABLE;
            }
        }
        else {
            apr_pool_cleanup_register(r->pool, daemon, wsgi_close_socket,
                                      apr_pool_cleanup_null);

            break;
        }
    }

    return OK;
}

static int wsgi_execute_remote(request_rec *r)
{
    WSGIRequestConfig *config = NULL;
    WSGIDaemonSocket *daemon = NULL;

    int status;

    /* Grab request configuration. */

    config = (WSGIRequestConfig *)ap_get_module_config(r->request_config,
                                                       &wsgi_module);

    /* Find socket path for target daemon process. */

    daemon = (WSGIDaemonSocket *)apr_pcalloc(r->pool,
                                             sizeof(WSGIDaemonSocket));

    daemon->name = config->process_name;

    if (wsgi_daemon_sockets)
        daemon->path = apr_table_get(wsgi_daemon_sockets, daemon->name);

    if (!daemon->path) {
        wsgi_log_script_error(r, apr_psprintf(r->pool, "No WSGI daemon "
                              "process called '%s' has been configured",
                              daemon->name), r->filename);

        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Creation connection to the daemon process. */

    status = wsgi_connect_daemon(r, daemon);

    if (status != OK)
        return status;

    /* XXX Haven't finished yet. */

    wsgi_log_script_error(r, "Sorry, proxying to a WSGI daemon process "
                          "is still being implemented", r->filename);

    return HTTP_INTERNAL_SERVER_ERROR;
}

#endif

/*
 * Apache 2.X module initialisation functions.
 */

static int wsgi_hook_init(apr_pool_t *pconf, apr_pool_t *ptemp,
                          apr_pool_t *plog, server_rec *s)
{
    void *data = NULL;
    const char *userdata_key = "wsgi_init";
    char package[128];

    int status = OK;

    /*
     * No need to perform init in Win32 parent processes as
     * the lack of fork on Win32 means we get no benefit as far
     * as inheriting a preinitialized Python interpreter.
     */

#if defined(WIN32)
    if (!getenv("AP_PARENT_PID"))
        return OK;
#endif

    /*
     * Init function gets called twice during startup, we only
     * need to actually do anything on the second time it is
     * called. This avoids unecessarily initialising and then
     * destroying Python for no reason.
     */

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /* Setup module version information. */

    sprintf(package, "mod_wsgi/%d.%d-TRUNK", MOD_WSGI_MAJORVERSION_NUMBER,
            MOD_WSGI_MINORVERSION_NUMBER);

    ap_add_version_component(pconf, package);

    /* Retain reference to main server config. */

    wsgi_server_config = ap_get_module_config(s->module_config, &wsgi_module);

    /* Initialise Python if not already done. */

    wsgi_python_init(pconf);

    /* Startup separate named daemon processes. */

#if !defined(WIN32)
    status = wsgi_start_daemons(pconf);
#endif

    return status;
}

static void wsgi_hook_child_init(apr_pool_t *p, server_rec *s)
{
    wsgi_python_child_init(p);
}

static void wsgi_register_hooks(apr_pool_t *p)
{
    static const char * const prev[] = { "mod_alias.c", NULL };
    static const char * const next[]= { "mod_userdir.c",
                                        "mod_vhost_alias.c", NULL };

    /*
     * Perform initialisation last in the post config phase to
     * ensure that if mod_python is also being loaded that it
     * gets to perform interpreter initialisation in preference
     * to mod_wsgi doing it.
     */

    ap_hook_post_config(wsgi_hook_init, NULL, NULL, APR_HOOK_LAST);
    ap_hook_child_init(wsgi_hook_child_init, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_translate_name(wsgi_hook_intercept, prev, next, APR_HOOK_MIDDLE);
    ap_hook_handler(wsgi_hook_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec wsgi_commands[] =
{
    AP_INIT_TAKE2("WSGIScriptAlias", wsgi_add_script_alias, NULL,
        RSRC_CONF, "Map location to target WSGI script file."),
    AP_INIT_TAKE2("WSGIScriptAliasMatch", wsgi_add_script_alias, "*",
        RSRC_CONF, "Map location pattern to target WSGI script file."),

#if !defined(WIN32)
    AP_INIT_RAW_ARGS("WSGIDaemonProcess", wsgi_add_daemon_process, NULL,
        RSRC_CONF, "Specify details of daemon process to start."),
    AP_INIT_TAKE1("WSGISocketPrefix", wsgi_set_socket_prefix, NULL,
        RSRC_CONF, "Path prefix for the daemon process sockets."),
#endif

    AP_INIT_TAKE1("WSGIPythonOptimize", wsgi_set_python_optimize, NULL,
        RSRC_CONF, "Enable/Disable Python compiler optimisations."),
    AP_INIT_TAKE1("WSGIRestrictStdin", wsgi_set_restrict_stdin, NULL,
        RSRC_CONF, "Enable/Disable restrictions on use of STDIN."),
    AP_INIT_TAKE1("WSGIRestrictStdout", wsgi_set_restrict_stdout, NULL,
        RSRC_CONF, "Enable/Disable restrictions on use of STDOUT."),
    AP_INIT_TAKE1("WSGIRestrictSignal", wsgi_set_restrict_signal, NULL,
        RSRC_CONF, "Enable/Disable restrictions on use of signal()."),

#if !defined(WIN32)
    AP_INIT_TAKE1("WSGIProcessName", wsgi_set_process_name, NULL,
        OR_FILEINFO, "Name of the WSGI daemon process to use."),
#endif

    AP_INIT_TAKE1("WSGIApplicationGroup", wsgi_set_application_group, NULL,
        OR_FILEINFO, "Name of the WSGI application group to use."),
    AP_INIT_TAKE1("WSGICallableObject", wsgi_set_callable_object, NULL,
        OR_FILEINFO, "Name of entry point in WSGI script file."),

    AP_INIT_TAKE1("WSGIPassAuthorization", wsgi_set_pass_authorization, NULL,
        OR_FILEINFO, "Enable/Disable passing authorization headers."),
    AP_INIT_TAKE1("WSGIScriptReloading", wsgi_set_script_reloading, NULL,
        OR_FILEINFO, "Enable/Disable script reloading mechanism."),
    AP_INIT_TAKE1("WSGIReloadMechanism", wsgi_set_reload_mechanism, NULL,
        OR_FILEINFO, "Defines what is reloaded when a reload occurs."),
    AP_INIT_TAKE1("WSGIOutputBuffering", wsgi_set_output_buffering, NULL,
        OR_FILEINFO, "Enable/Disable buffering of response."),

    { NULL }
};

/* Dispatch list for API hooks */

module AP_MODULE_DECLARE_DATA wsgi_module = {
    STANDARD20_MODULE_STUFF,
    wsgi_create_dir_config,    /* create per-dir    config structures */
    wsgi_merge_dir_config,     /* merge  per-dir    config structures */
    wsgi_create_server_config, /* create per-server config structures */
    wsgi_merge_server_config,  /* merge  per-server config structures */
    wsgi_commands,             /* table of config file commands       */
    wsgi_register_hooks        /* register hooks                      */
};

#endif
