dnl  vim: set sw=4 expandtab :
dnl
dnl  Copyright 2007-2008 GRAHAM DUMPLETON
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

AC_INIT(mod_wsgi.c)

AC_ARG_ENABLE(embedded, AC_HELP_STRING([--disable-embedded],
            [disable mod_wsgi embedded mode]),
            [ENABLE_EMBEDDED=$enableval],
	    [ENABLE_EMBEDDED=yes])

AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of the apxs executable [[apxs]]]),
            [APXS="$with_apxs"])

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, [apxs],
                   [$PATH:/usr/local/apache/bin:/usr/sbin])
fi

AC_SUBST(APXS)

AC_MSG_CHECKING(Apache version)
HTTPD="`${APXS} -q SBINDIR`/`${APXS} -q TARGET`"
HTTPD_VERSION=`$HTTPD -v | awk '/version/ {print $3}' | awk -F/ '{print $2}'`
AC_MSG_RESULT($HTTPD_VERSION)

AC_ARG_WITH(python, AC_HELP_STRING([--with-python=NAME],
            [name of the python executable [[python]]]),
            [PYTHON="$with_python"])

if test -z "${PYTHON}"; then
    AC_PATH_PROGS(PYTHON, python, [python],
                   [$PATH:/usr/local/bin])
fi

AC_SUBST(PYTHON)

PYTHON_VERSION=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write((sysconfig.get_config_var("VERSION")))'`

CPPFLAGS1=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write("-I" + sysconfig.get_config_var("INCLUDEPY"))'`

CPPFLAGS2=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(" ".join(filter(lambda x: x.startswith("-D"), \
    sysconfig.get_config_var("CFLAGS").split())))'`

if test "${ENABLE_EMBEDDED}" != "yes"; then
CPPFLAGS3="-DMOD_WSGI_DISABLE_EMBEDDED"
else
CPPFLAGS3=""
fi

CPPFLAGS="${CPPFLAGS} ${CPPFLAGS1} ${CPPFLAGS2} ${CPPFLAGS3}"

AC_SUBST(CPPFLAGS)

PYTHONLIBDIR=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("LIBDIR"))'`
PYTHONFRAMEWORKDIR=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("PYTHONFRAMEWORKDIR"))'`
PYTHONFRAMEWORKPREFIX=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX"))'`
PYTHONFRAMEWORK=`${PYTHON} -c 'from sys import stdout; \
    from distutils import sysconfig; \
    stdout.write(sysconfig.get_config_var("PYTHONFRAMEWORK"))'`

if test "${PYTHONFRAMEWORKDIR}" = "no-framework"; then
    LDFLAGS1="-L${PYTHONLIBDIR}"
    LDFLAGS2=`${PYTHON} -c 'from sys import stdout; \
        import distutils.sysconfig; \
        stdout.write("-L" + \
        distutils.sysconfig.get_python_lib(plat_specific=1, \
        standard_lib=1) +"/config")'`

    LDLIBS1="-lpython${PYTHON_VERSION}"
    LDLIBS2=`${PYTHON} -c 'from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var("LIBS"))'`
    LDLIBS3=`${PYTHON} -c 'from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var("SYSLIBS"))'`
else
    LDFLAGS1="-F${PYTHONFRAMEWORKPREFIX} -framework ${PYTHONFRAMEWORK}"

    VERSION="${PYTHON_VERSION}"
    STRING="${PYTHONFRAMEWORKDIR}/Versions/${VERSION}/${PYTHONFRAMEWORK}"
    LDFLAGS2=`${PYTHON} -c "from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var(\"LINKFORSHARED\").replace( \
        \"${STRING}\", ''))"`

    LDLIBS1=`${PYTHON} -c 'from sys import stdout; \
        from distutils import sysconfig; \
        stdout.write(sysconfig.get_config_var("LIBS"))'`
fi

CFLAGS=""
if test -x /usr/bin/lipo; then
    LDFLAGS3=""
    ARCHITECTURES=`/usr/bin/lipo -info $HTTPD | sed -e 's/.*://'`
    for ARCH in $ARCHITECTURES; do
        CFLAGS="${CFLAGS} -Wc,'-arch ${ARCH}'" 
        LDFLAGS3="${LDFLAGS3} -arch ${ARCH}" 
    done
fi

LDFLAGS="${LDFLAGS} ${LDFLAGS1} ${LDFLAGS2} ${LDFLAGS3}"
LDLIBS="${LDLIBS} ${LDLIBS1} ${LDLIBS2} ${LDLIBS3}"

LDFLAGS=`echo ${LDFLAGS} | \
 sed -e "s/-Wl,\([[^ ]][[^ ]]*\)/\1/g" -e "s/\([[^ ]][[^ ]]*\)/-Wl,\1/g"`
LDLIBS=`echo ${LDLIBS} | \
 sed -e "s/-Wl,\([[^ ]][[^ ]]*\)/\1/g" -e "s/\([[^ ]][[^ ]]*\)/-Wl,\1/g"`

AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(LDLIBS)

LIBEXECDIR="`${APXS} -q LIBEXECDIR`"
AC_SUBST(LIBEXECDIR)

HTTPD_MAJOR_VERSION=`echo ${HTTPD_VERSION} | sed -e 's/\..*//'`

rm -f Makefile.in
ln -s Makefile-${HTTPD_MAJOR_VERSION}.X.in Makefile.in

AC_OUTPUT(Makefile)
