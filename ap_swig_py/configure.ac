dnl  vim: set sw=4 expandtab :
dnl
dnl  Copyright 2007 GRAHAM DUMPLETON
dnl 
dnl  Licensed under the Apache License, Version 2.0 (the "License");
dnl  you may not use this file except in compliance with the License.
dnl  You may obtain a copy of the License at
dnl 
dnl      http://www.apache.org/licenses/LICENSE-2.0
dnl 
dnl  Unless required by applicable law or agreed to in writing, software
dnl  distributed under the License is distributed on an "AS IS" BASIS,
dnl  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl  See the License for the specific language governing permissions and
dnl  limitations under the License.

dnl Process this file with autoconf to produce a configure script.

AC_INIT(setup.py.in)

AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of the apxs executable [[apxs]]]),
            [APXS="$with_apxs"])

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, [apxs],
                  [$PATH:/usr/local/apache/bin:/usr/sbin])
fi

AC_SUBST(APXS)

AC_ARG_WITH(python, AC_HELP_STRING([--with-python=NAME],
            [name of the python executable [[python]]]),
            [PYTHON="$with_python"])

if test -z "${PYTHON}"; then
        AC_PATH_PROGS(PYTHON, python, [python],
                      [$PATH:/usr/local/bin])
fi

AC_SUBST(PYTHON)

AC_ARG_WITH(swig, AC_HELP_STRING([--with-swig=NAME],
            [name of the swig executable [[swig]]]),
            [SWIG="$with_swig"])

if test -z "${SWIG}"; then
    AC_PATH_PROGS(SWIG, swig, [swig],
                  [$PATH:/usr/local/bin])
fi

AC_SUBST(SWIG)

AC_OUTPUT(Makefile setup.py)
