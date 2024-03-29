/* -*- buffer-read-only: t -*- vi: set ro: */
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
#line 1
/* Test duplicating file descriptors.
   Copyright (C) 2009 Free Software Foundation, Inc.

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

/* Written by Eric Blake <ebb9@byu.net>, 2009.  */

#include <config.h>

#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#if (defined _WIN32 || defined __WIN32__) && ! defined __CYGWIN__
/* Get declarations of the Win32 API functions.  */
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif

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

/* Return non-zero if FD is open.  */
static int
is_open (int fd)
{
#if (defined _WIN32 || defined __WIN32__) && ! defined __CYGWIN__
  /* On Win32, the initial state of unassigned standard file
     descriptors is that they are open but point to an
     INVALID_HANDLE_VALUE, and there is no fcntl.  */
  return (HANDLE) _get_osfhandle (fd) != INVALID_HANDLE_VALUE;
#else
# ifndef F_GETFL
#  error Please port fcntl to your platform
# endif
  return 0 <= fcntl (fd, F_GETFL);
#endif
}

int
main (void)
{
  const char *file = "test-dup2.tmp";
  char buffer[1];
  int fd = open (file, O_CREAT | O_TRUNC | O_RDWR, 0600);

  /* Assume std descriptors were provided by invoker.  */
  ASSERT (STDERR_FILENO < fd);
  ASSERT (is_open (fd));
  /* Ignore any other fd's leaked into this process.  */
  close (fd + 1);
  close (fd + 2);
  ASSERT (!is_open (fd + 1));
  ASSERT (!is_open (fd + 2));

  /* Assigning to self must be a no-op.  */
  ASSERT (dup2 (fd, fd) == fd);
  ASSERT (is_open (fd));

  /* The source must be valid.  */
  errno = 0;
  ASSERT (dup2 (-1, fd) == -1);
  ASSERT (errno == EBADF);
  errno = 0;
  ASSERT (dup2 (AT_FDCWD, fd) == -1);
  ASSERT (errno == EBADF);
  ASSERT (is_open (fd));

  /* If the source is not open, then the destination is unaffected.  */
  errno = 0;
  ASSERT (dup2 (fd + 1, fd + 1) == -1);
  ASSERT (errno == EBADF);
  ASSERT (!is_open (fd + 1));
  errno = 0;
  ASSERT (dup2 (fd + 1, fd) == -1);
  ASSERT (errno == EBADF);
  ASSERT (is_open (fd));

  /* The destination must be valid.  */
  errno = 0;
  ASSERT (dup2 (fd, -2) == -1);
  ASSERT (errno == EBADF);
  errno = 0;
  ASSERT (dup2 (fd, 10000000) == -1);
  ASSERT (errno == EBADF);

  /* Using dup2 can skip fds.  */
  ASSERT (dup2 (fd, fd + 2) == fd + 2);
  ASSERT (is_open (fd));
  ASSERT (!is_open (fd + 1));
  ASSERT (is_open (fd + 2));

  /* Verify that dup2 closes the previous occupant of a fd.  */
  ASSERT (open ("/dev/null", O_WRONLY, 0600) == fd + 1);
  ASSERT (dup2 (fd + 1, fd) == fd);
  ASSERT (close (fd + 1) == 0);
  ASSERT (write (fd, "1", 1) == 1);
  ASSERT (dup2 (fd + 2, fd) == fd);
  ASSERT (lseek (fd, 0, SEEK_END) == 0);
  ASSERT (write (fd + 2, "2", 1) == 1);
  ASSERT (lseek (fd, 0, SEEK_SET) == 0);
  ASSERT (read (fd, buffer, 1) == 1);
  ASSERT (*buffer == '2');

  /* Clean up.  */
  ASSERT (close (fd + 2) == 0);
  ASSERT (close (fd) == 0);
  ASSERT (unlink (file) == 0);

  return 0;
}
