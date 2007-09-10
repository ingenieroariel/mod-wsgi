/* vim: set sw=4 expandtab : */

/*
 * Apache 1.3 didn't have a separate 'apr_strings.h' so need to
 * fake up minimal module with what equivalent functions existed
 * and which were usable.
 */

%module(package="mod_grumpy.bindings.apache13") apr_strings

%{
#include "ap_config.h"
#include "ap_alloc.h"
%}

%nodefaultctor;
%nodefaultdtor;

%immutable;

%feature("python:nondynamic","1");

#define API_EXPORT(type) type
#define API_EXPORT_NONSTD(type) type
#define __attribute__(value)

%rename(apr_pstrdup) ap_pstrdup;
%rename(apr_pstrndup) ap_pstrndup;
%rename(apr_pstrcat) ap_pstrcat;
%rename(apr_psprintf) ap_psprintf;
%rename(apr_pvsprintf) ap_pvsprintf;

%ignore ap_init_alloc;
%ignore ap_cleanup_alloc;
%ignore ap_make_sub_pool;
%ignore ap_destroy_pool;
%ignore ap_clear_pool;
%ignore ap_cleanup_for_exec;
%ignore ap_palloc;
%ignore ap_pcalloc;
%ignore array_header;
%ignore ap_make_array;
%ignore ap_push_array;
%ignore ap_array_cat;
%ignore ap_append_arrays;
%ignore ap_array_pstrcat;
%ignore ap_copy_array;
%ignore ap_copy_array_hdr;
%ignore table_entry;
%ignore ap_make_table;
%ignore ap_copy_table;
%ignore ap_clear_table;
%ignore ap_table_get;
%ignore ap_table_set;
%ignore ap_table_setn;
%ignore ap_table_merge;
%ignore ap_table_mergen;
%ignore ap_table_unset;
%ignore ap_table_add;
%ignore ap_table_addn;
%ignore ap_table_do;
%ignore ap_overlay_tables;
%ignore AP_OVERLAP_TABLES_SET;
%ignore AP_OVERLAP_TABLES_MERGE;
%ignore ap_overlap_tables;
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

%include "ap_alloc.h"
