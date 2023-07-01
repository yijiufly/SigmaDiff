# Check for variable-length arrays.

#serial 2

# From Paul Eggert

# Copyright (C) 2001, 2009-2011 Free Software Foundation, Inc.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_DEFUN([AC_C_VARARRAYS],
[
  AC_CACHE_CHECK([for variable-length arrays],
    ac_cv_c_vararrays,
    [AC_TRY_COMPILE(
       [],
       [static int x; char a[++x]; a[sizeof a - 1] = 0; return a[0];],
       ac_cv_c_vararrays=yes,
       ac_cv_c_vararrays=no)])
  if test $ac_cv_c_vararrays = yes; then
    AC_DEFINE([HAVE_C_VARARRAYS], [1],
      [Define to 1 if C supports variable-length arrays.])
  fi
])
