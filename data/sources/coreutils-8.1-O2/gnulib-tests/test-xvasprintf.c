/* -*- buffer-read-only: t -*- vi: set ro: */
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
#line 1
/* Test of xvasprintf() and xasprintf() functions.
   Copyright (C) 2007-2009 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Bruno Haible <bruno@clisp.org>, 2007.  */

#include <config.h>

#include "xvasprintf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "progname.h"

#define ASSERT(expr) \
  do									     \
    {									     \
      if (!(expr))							     \
        {								     \
          fprintf (stderr, "%s:%d: assertion failed\n", __FILE__, __LINE__); \
          fflush (stderr);						     \
          abort ();							     \
        }								     \
    }									     \
  while (0)

static char *
my_xasprintf (const char *format, ...)
{
  va_list args;
  char *ret;

  va_start (args, format);
  ret = xvasprintf (format, args);
  va_end (args);
  return ret;
}

static void
test_xvasprintf (void)
{
  int repeat;
  char *result;

  for (repeat = 0; repeat <= 8; repeat++)
    {
      result = my_xasprintf ("%d", 12345);
      ASSERT (result != NULL);
      ASSERT (strcmp (result, "12345") == 0);
      free (result);
    }

  result = my_xasprintf ("");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "") == 0);
  free (result);

  result = my_xasprintf ("%s", "foo");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "foo") == 0);
  free (result);

  result = my_xasprintf ("%s%s", "foo", "bar");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "foobar") == 0);
  free (result);

  result = my_xasprintf ("%s%sbaz", "foo", "bar");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "foobarbaz") == 0);
  free (result);
}

static void
test_xasprintf ()
{
  int repeat;
  char *result;

  for (repeat = 0; repeat <= 8; repeat++)
    {
      result = xasprintf ("%d", 12345);
      ASSERT (result != NULL);
      ASSERT (strcmp (result, "12345") == 0);
      free (result);
    }

  result = xasprintf ("");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "") == 0);
  free (result);

  result = xasprintf ("%s", "foo");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "foo") == 0);
  free (result);

  result = xasprintf ("%s%s", "foo", "bar");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "foobar") == 0);
  free (result);

  result = my_xasprintf ("%s%sbaz", "foo", "bar");
  ASSERT (result != NULL);
  ASSERT (strcmp (result, "foobarbaz") == 0);
  free (result);
}

int
main (int argc _UNUSED_PARAMETER_, char *argv[])
{
  set_program_name (argv[0]);

  test_xvasprintf ();
  test_xasprintf ();

  return 0;
}
