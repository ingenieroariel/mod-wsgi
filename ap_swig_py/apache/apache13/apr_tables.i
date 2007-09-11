/* vim: set sw=4 expandtab : */

/*
 * Apache 1.3 didn't have a separate 'apr_tables.h' so need to
 * fake up minimal module with what equivalent functions existed
 * and which were usable.
 */

%module(package="apache.apache13") apr_tables

%{
#include "ap_config.h"
#include "ap_alloc.h"
typedef pool apr_pool_t;
typedef table apr_table_t;
typedef table_entry apr_table_entry_t;
typedef array_header apr_array_header_t;
#define apr_table_elts ap_table_elts
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type
#define __attribute__(value)

struct table {};

%rename(apr_array_make) ap_make_array;
%rename(apr_array_push) ap_push_array;
%rename(apr_array_cat) ap_array_cat;
%rename(apr_array_append) ap_append_arrays;
%rename(apr_array_pstrcat) ap_array_pstrcat;
%rename(apr_array_copy) ap_copy_array;
%rename(apr_array_copy_hdr) ap_copy_array_hdr;

%rename(apr_table_make) ap_make_table;
%rename(apr_table_copy) ap_copy_table;
%rename(apr_table_clear) ap_clear_table;
%rename(apr_table_get) ap_table_get;
%rename(apr_table_set) ap_table_set;
%rename(apr_table_setn) ap_table_setn;
%rename(apr_table_merge) ap_table_merge;
%rename(apr_table_mergen) ap_table_mergen;
%rename(apr_table_unset) ap_table_unset;
%rename(apr_table_add) ap_table_add;
%rename(apr_table_addn) ap_table_addn;
%rename(apr_table_do) ap_table_do;
%rename(apr_table_overlay) ap_overlay_tables;
%rename(APR_OVERLAP_TABLES_SET) AP_OVERLAP_TABLES_SET;
%rename(APR_OVERLAP_TABLES_MERGE) AP_OVERLAP_TABLES_MERGE;
%rename(apr_table_overlap) ap_overlap_tables;

%rename(apr_table_elts) ap_table_elts;
extern const array_header *ap_table_elts(const table *t);
%rename(apr_is_empty_table) ap_is_empty_table;
extern int ap_is_empty_table(const table *t);

%ignore ap_init_alloc;
%ignore ap_cleanup_alloc;
%ignore ap_make_sub_pool;
%ignore ap_destroy_pool;
%ignore ap_clear_pool;
%ignore ap_cleanup_for_exec;
%ignore ap_palloc;
%ignore ap_pcalloc;
%ignore ap_pstrdup;
%ignore ap_pstrndup;
%ignore ap_pstrcat;
%ignore ap_psprintf;
%ignore ap_pvsprintf;
%ignore ap_register_cleanup;
%ignore ap_register_cleanup_ex;
%ignore ap_kill_cleanup;
%ignore ap_run_cleanup;
%ignore ap_null_cleanup;
%ignore ap_block_alarms;
%ignore ap_unblock_alarms;
%ignore ap_pfopen;
%ignore ap_pfdopen;
%ignore ap_popenf;
%ignore ap_popenf_ex;
%ignore ap_note_cleanups_for_file;
%ignore ap_note_cleanups_for_file_ex;
%ignore ap_note_cleanups_for_fd;
%ignore ap_note_cleanups_for_fd_ex;
%ignore ap_kill_cleanups_for_fd;
%ignore ap_note_cleanups_for_socket;
%ignore ap_note_cleanups_for_socket_ex;
%ignore ap_kill_cleanups_for_socket;
%ignore ap_psocket;
%ignore ap_psocket_ex;
%ignore ap_pclosesocket;
%ignore ap_pregcomp;
%ignore ap_pregfree;
%ignore ap_pfclose;
%ignore ap_pclosef;
%ignore ap_popendir;
%ignore ap_pclosedir;
%ignore kill_never;
%ignore kill_always;
%ignore kill_after_timeout;
%ignore just_wait;
%ignore kill_only_once;
%ignore ap_note_subprocess;
%ignore ap_spawn_child;
%ignore ap_close_fd_on_exec;
%ignore BLOCK_MINFREE;
%ignore BLOCK_MINALLOC;
%ignore ap_bytes_in_pool;
%ignore ap_bytes_in_free_blocks;

#define apr_table_t table
#define apr_table_entry_t table_entry

%import "../_apr_tables.i"

%include "ap_alloc.h"
