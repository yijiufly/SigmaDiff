/* -*- buffer-read-only: t -*- vi: set ro: */
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
#line 1
/* Test of command line argument processing.
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

/* Written by Bruno Haible <bruno@clisp.org>, 2009.  */

static void
getopt_loop (int argc, const char **argv,
	     const char *options,
	     int *a_seen, int *b_seen,
	     const char **p_value, const char **q_value,
	     int *non_options_count, const char **non_options,
	     int *unrecognized)
{
  int c;

  opterr = 0;
  while ((c = getopt (argc, (char **) argv, options)) != -1)
    {
      switch (c)
	{
	case 'a':
	  (*a_seen)++;
	  break;
	case 'b':
	  (*b_seen)++;
	  break;
	case 'p':
	  *p_value = optarg;
	  break;
	case 'q':
	  *q_value = optarg;
	  break;
	case '\1':
	  /* Must only happen with option '-' at the beginning.  */
	  ASSERT (options[0] == '-');
	  non_options[(*non_options_count)++] = optarg;
	  break;
	case '?':
	  *unrecognized = optopt;
	  break;
	default:
	  *unrecognized = c;
	  break;
	}
    }
}

static void
test_getopt (void)
{
  int start;

  /* Test processing of boolean options.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-a";
      argv[argc++] = "foo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "ab",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 2);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-b";
      argv[argc++] = "-a";
      argv[argc++] = "foo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "ab",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 1);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 3);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-ba";
      argv[argc++] = "foo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "ab",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 1);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 2);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-ab";
      argv[argc++] = "-a";
      argv[argc++] = "foo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "ab",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 2);
      ASSERT (b_seen == 1);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 3);
    }

  /* Test processing of options with arguments.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-pfoo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "p:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "foo") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 2);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-p";
      argv[argc++] = "foo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "p:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "foo") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 3);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-ab";
      argv[argc++] = "-q";
      argv[argc++] = "baz";
      argv[argc++] = "-pfoo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 1);
      ASSERT (p_value != NULL && strcmp (p_value, "foo") == 0);
      ASSERT (q_value != NULL && strcmp (q_value, "baz") == 0);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 5);
    }

#if GNULIB_GETOPT_GNU
  /* Test processing of options with optional arguments.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-pfoo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "p::q::",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "foo") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 2);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-p";
      argv[argc++] = "foo";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "p::q::",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 2);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-p";
      argv[argc++] = "-a";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "abp::q::",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 3);
    }
#endif

  /* Check that invalid options are recognized.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-p";
      argv[argc++] = "foo";
      argv[argc++] = "-x";
      argv[argc++] = "-a";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "foo") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 'x');
      ASSERT (optind == 5);
    }

  /* Check that by default, non-options arguments are moved to the end.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      /* See comment in getopt.c:
         glibc gets a LSB-compliant getopt.
         Standalone applications get a POSIX-compliant getopt.  */
#if defined __GETOPT_PREFIX || !(__GLIBC__ >= 2 || defined __MINGW32__)
      /* Using getopt from gnulib or from a non-glibc system.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 1);
#else
      /* Using getopt from glibc.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "-p") == 0);
      ASSERT (strcmp (argv[2], "billy") == 0);
      ASSERT (strcmp (argv[3], "-a") == 0);
      ASSERT (strcmp (argv[4], "donald") == 0);
      ASSERT (strcmp (argv[5], "duck") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "billy") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 4);
#endif
    }

  /* Check that '--' ends the argument processing.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[20];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "--";
      argv[argc++] = "-b";
      argv[argc++] = "foo";
      argv[argc++] = "-q";
      argv[argc++] = "johnny";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      /* See comment in getopt.c:
         glibc gets a LSB-compliant getopt.
         Standalone applications get a POSIX-compliant getopt.  */
#if defined __GETOPT_PREFIX || !(__GLIBC__ >= 2 || defined __MINGW32__)
      /* Using getopt from gnulib or from a non-glibc system.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "--") == 0);
      ASSERT (strcmp (argv[7], "-b") == 0);
      ASSERT (strcmp (argv[8], "foo") == 0);
      ASSERT (strcmp (argv[9], "-q") == 0);
      ASSERT (strcmp (argv[10], "johnny") == 0);
      ASSERT (strcmp (argv[11], "bar") == 0);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 1);
#else
      /* Using getopt from glibc.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "-p") == 0);
      ASSERT (strcmp (argv[2], "billy") == 0);
      ASSERT (strcmp (argv[3], "-a") == 0);
      ASSERT (strcmp (argv[4], "--") == 0);
      ASSERT (strcmp (argv[5], "donald") == 0);
      ASSERT (strcmp (argv[6], "duck") == 0);
      ASSERT (strcmp (argv[7], "-b") == 0);
      ASSERT (strcmp (argv[8], "foo") == 0);
      ASSERT (strcmp (argv[9], "-q") == 0);
      ASSERT (strcmp (argv[10], "johnny") == 0);
      ASSERT (strcmp (argv[11], "bar") == 0);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "billy") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 5);
#endif
    }

#if GNULIB_GETOPT_GNU
  /* Check that the '-' flag causes non-options to be returned in order.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "-abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "billy") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 3);
      ASSERT (strcmp (non_options[0], "donald") == 0);
      ASSERT (strcmp (non_options[1], "duck") == 0);
      ASSERT (strcmp (non_options[2], "bar") == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 7);
    }

  /* Check that '--' ends the argument processing.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[20];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "--";
      argv[argc++] = "-b";
      argv[argc++] = "foo";
      argv[argc++] = "-q";
      argv[argc++] = "johnny";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "-abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "--") == 0);
      ASSERT (strcmp (argv[7], "-b") == 0);
      ASSERT (strcmp (argv[8], "foo") == 0);
      ASSERT (strcmp (argv[9], "-q") == 0);
      ASSERT (strcmp (argv[10], "johnny") == 0);
      ASSERT (strcmp (argv[11], "bar") == 0);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "billy") == 0);
      ASSERT (q_value == NULL);
      if (non_options_count == 2)
        {
	  /* glibc behaviour.  */
	  ASSERT (non_options_count == 2);
	  ASSERT (strcmp (non_options[0], "donald") == 0);
	  ASSERT (strcmp (non_options[1], "duck") == 0);
	  ASSERT (unrecognized == 0);
	  ASSERT (optind == 7);
        }
      else
        {
	  /* Another valid behaviour.  */
	  ASSERT (non_options_count == 7);
	  ASSERT (strcmp (non_options[0], "donald") == 0);
	  ASSERT (strcmp (non_options[1], "duck") == 0);
	  ASSERT (strcmp (non_options[2], "-b") == 0);
	  ASSERT (strcmp (non_options[3], "foo") == 0);
	  ASSERT (strcmp (non_options[4], "-q") == 0);
	  ASSERT (strcmp (non_options[5], "johnny") == 0);
	  ASSERT (strcmp (non_options[6], "bar") == 0);
	  ASSERT (unrecognized == 0);
	  ASSERT (optind == 12);
        }
    }
#endif

  /* Check that the '-' flag has to come first.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "abp:q:-",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      /* See comment in getopt.c:
         glibc gets a LSB-compliant getopt.
         Standalone applications get a POSIX-compliant getopt.  */
#if defined __GETOPT_PREFIX || !(__GLIBC__ >= 2 || defined __MINGW32__)
      /* Using getopt from gnulib or from a non-glibc system.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 1);
#else
      /* Using getopt from glibc.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "-p") == 0);
      ASSERT (strcmp (argv[2], "billy") == 0);
      ASSERT (strcmp (argv[3], "-a") == 0);
      ASSERT (strcmp (argv[4], "donald") == 0);
      ASSERT (strcmp (argv[5], "duck") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "billy") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 4);
#endif
    }

  /* Check that the '+' flag causes the first non-option to terminate the
     loop.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "+abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 1);
    }
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "-+";
      optind = start;
      getopt_loop (argc, argv, "+abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == '+');
      ASSERT (optind == 2);
    }

  /* Check that '--' ends the argument processing.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[20];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "--";
      argv[argc++] = "-b";
      argv[argc++] = "foo";
      argv[argc++] = "-q";
      argv[argc++] = "johnny";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "+abp:q:",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "--") == 0);
      ASSERT (strcmp (argv[7], "-b") == 0);
      ASSERT (strcmp (argv[8], "foo") == 0);
      ASSERT (strcmp (argv[9], "-q") == 0);
      ASSERT (strcmp (argv[10], "johnny") == 0);
      ASSERT (strcmp (argv[11], "bar") == 0);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind = 1);
    }

  /* Check that the '+' flag has to come first.  */
  for (start = OPTIND_MIN; start <= 1; start++)
    {
      int a_seen = 0;
      int b_seen = 0;
      const char *p_value = NULL;
      const char *q_value = NULL;
      int non_options_count = 0;
      const char *non_options[10];
      int unrecognized = 0;
      int argc = 0;
      const char *argv[10];

      argv[argc++] = "program";
      argv[argc++] = "donald";
      argv[argc++] = "-p";
      argv[argc++] = "billy";
      argv[argc++] = "duck";
      argv[argc++] = "-a";
      argv[argc++] = "bar";
      optind = start;
      getopt_loop (argc, argv, "abp:q:+",
		   &a_seen, &b_seen, &p_value, &q_value,
		   &non_options_count, non_options, &unrecognized);
      /* See comment in getopt.c:
         glibc gets a LSB-compliant getopt.
         Standalone applications get a POSIX-compliant getopt.  */
#if defined __GETOPT_PREFIX || !(__GLIBC__ >= 2 || defined __MINGW32__)
      /* Using getopt from gnulib or from a non-glibc system.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "donald") == 0);
      ASSERT (strcmp (argv[2], "-p") == 0);
      ASSERT (strcmp (argv[3], "billy") == 0);
      ASSERT (strcmp (argv[4], "duck") == 0);
      ASSERT (strcmp (argv[5], "-a") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 0);
      ASSERT (b_seen == 0);
      ASSERT (p_value == NULL);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 1);
#else
      /* Using getopt from glibc.  */
      ASSERT (strcmp (argv[0], "program") == 0);
      ASSERT (strcmp (argv[1], "-p") == 0);
      ASSERT (strcmp (argv[2], "billy") == 0);
      ASSERT (strcmp (argv[3], "-a") == 0);
      ASSERT (strcmp (argv[4], "donald") == 0);
      ASSERT (strcmp (argv[5], "duck") == 0);
      ASSERT (strcmp (argv[6], "bar") == 0);
      ASSERT (a_seen == 1);
      ASSERT (b_seen == 0);
      ASSERT (p_value != NULL && strcmp (p_value, "billy") == 0);
      ASSERT (q_value == NULL);
      ASSERT (non_options_count == 0);
      ASSERT (unrecognized == 0);
      ASSERT (optind == 4);
#endif
    }
}
