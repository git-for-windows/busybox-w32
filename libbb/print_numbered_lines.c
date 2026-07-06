/* vi: set sw=4 ts=4: */
/*
 * Copyright (C) 2017 Denys Vlasenko <vda.linux@googlemail.com>
 *
 * Licensed under GPLv2, see file LICENSE in this source tree.
 */
//kbuild:lib-y += print_numbered_lines.o

#include "libbb.h"

static FILE *numbered_fp;
static void (*numbered_next_die_func)(void);

static void numbered_input_cleanup_and_die(void)
{
	FILE *fp = numbered_fp;

	numbered_fp = NULL;
	die_func = numbered_next_die_func;
	if (fp)
		fclose_if_not_stdin(fp);
	if (die_func)
		die_func();
}

int FAST_FUNC print_numbered_lines(struct number_state *ns, const char *filename)
{
	FILE *fp;
	unsigned N;
	char *line;

	if (bb_nofork_signal)
		return EXIT_FAILURE;
	fp = fopen_or_warn_stdin(filename);
	if (!fp)
		return EXIT_FAILURE;
	if (fp == stdin) {
		int fd = dup(STDIN_FILENO);

		/* Do not leave read-ahead in the caller's redirected stdin. */
		fp = fd < 0 ? NULL : fdopen(fd, "r");
		if (!fp) {
			int saved_errno = errno;

			if (fd >= 0)
				close(fd);
			errno = saved_errno;
			bb_simple_perror_msg(bb_msg_standard_input);
			return EXIT_FAILURE;
		}
	}

	numbered_fp = fp;
	numbered_next_die_func = die_func;
	die_func = numbered_input_cleanup_and_die;

	N = ns->start;
	while ((line = xmalloc_fgetline(fp)) != NULL) {
		if (ns->all
		 || (ns->nonempty && line[0])
		) {
			printf("%*u%s", ns->width, N, ns->sep);
			N += ns->inc;
		} else if (ns->empty_str)
			fputs_stdout(ns->empty_str);
		puts(line);
		free(line);
	}
	ns->start = N;

	die_func = numbered_next_die_func;
	numbered_fp = NULL;
	fclose_if_not_stdin(fp);

	return bb_nofork_signal ? EXIT_FAILURE : EXIT_SUCCESS;
}
