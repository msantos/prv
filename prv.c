/* Copyright (c) 2017-2023, Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <err.h>
#include <getopt.h>
#include <sys/param.h>
#include <time.h>

#include <errno.h>
#include <fcntl.h>

#ifndef HAVE_STRTONUM
#include "strtonum.h"
#endif
#include "getnline.h"
#include "restrict_process.h"

#ifdef CLOCK_MONOTONIC_COARSE
#define PRV_CLOCK_MONOTONIC CLOCK_MONOTONIC_COARSE
#else
#define PRV_CLOCK_MONOTONIC CLOCK_MONOTONIC
#endif

#define PRV_VERSION "1.0.1"

enum { PRV_WR_BLOCK = 0, PRV_WR_DROP, PRV_WR_EXIT };

typedef struct {
  int verbose;
  size_t limit;
  size_t count;
  int window;
  struct timespec t0;
  int write_error;
} prv_state_t;

static int prv_input(prv_state_t *s);
static size_t prv_output(prv_state_t *s, char *buf, size_t buflen);
static void usage(void);

extern char *__progname;

#define VERBOSE(__s, __n, ...)                                                 \
  do {                                                                         \
    if (__s->verbose >= __n) {                                                 \
      (void)fprintf(stderr, __VA_ARGS__);                                      \
    }                                                                          \
  } while (0)

static const struct option long_options[] = {
    {"limit", required_argument, NULL, 'l'},
    {"window", required_argument, NULL, 'w'},
    {"write-error", required_argument, NULL, 'W'},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};

int main(int argc, char *argv[]) {
  int ch;
  prv_state_t s = {0};
  const char *errstr = NULL;

  if (restrict_process_init() < 0)
    err(3, "restrict_process_init");

  s.window = 1;

  if (setvbuf(stdout, NULL, _IOLBF, 0) < 0)
    err(EXIT_FAILURE, "setvbuf");

  while ((ch = getopt_long(argc, argv, "l:hw:W:v", long_options, NULL)) != -1) {
    switch (ch) {
    case 'l':
      s.limit = strtonum(optarg, 0, 0xffff, &errstr);
      if (errstr != NULL)
        errx(2, "strtonum: %s", errstr);
      break;
    case 'w':
      s.window = strtonum(optarg, 1, 0xffff, &errstr);
      if (errstr != NULL)
        errx(2, "strtonum: %s", errstr);
      break;
    case 'W':
      if (strcmp(optarg, "block") == 0)
        s.write_error = PRV_WR_BLOCK;
      else if (strcmp(optarg, "drop") == 0)
        s.write_error = PRV_WR_DROP;
      else if (strcmp(optarg, "exit") == 0)
        s.write_error = PRV_WR_EXIT;
      else
        errx(2, "invalid option: %s: block|drop|exit", optarg);

      break;
    case 'v':
      s.verbose += 1;
      break;
    case 'h':
      usage();
      exit(0);
    default:
      usage();
      exit(2);
    }
  }

  if (s.write_error != PRV_WR_BLOCK &&
      fcntl(fileno(stdout), F_SETFL, O_NONBLOCK) < 0)
    err(EXIT_FAILURE, "fcntl");

  if (clock_gettime(PRV_CLOCK_MONOTONIC, &(s.t0)) < 0)
    err(EXIT_FAILURE, "clock_gettime(CLOCK_MONOTONIC)");

  if (restrict_process_stdin() < 0)
    err(3, "restrict_process_stdin");

  if (prv_input(&s) < 0)
    err(111, "prv_input");

  exit(0);
}

static int prv_input(prv_state_t *s) {
  char *buf = NULL;
  size_t buflen = 0;
  ssize_t n;

  while ((n = getnline(&buf, &buflen, 4096, stdin)) != -1) {
    if (prv_output(s, buf, n) != (size_t)n) {
      switch (errno) {
      case 0:
        goto PRV_EOF;
      case EAGAIN:
        VERBOSE(s, 1, "PIPE FULL:dropped:%s", buf);
        if (s->write_error == PRV_WR_DROP)
          continue;
        /* fallthrough */
      default:
        return -1;
      }
    }
  }

PRV_EOF:
  free(buf);
  if (ferror(stdin))
    return -1;
  return 0;
}

static size_t prv_output(prv_state_t *s, char *buf, size_t buflen) {
  struct timespec t1;
  int sec;

  if (clock_gettime(PRV_CLOCK_MONOTONIC, &t1) < 0)
    err(EXIT_FAILURE, "clock_gettime(CLOCK_MONOTONIC)");

  sec = t1.tv_sec - s->t0.tv_sec;

  if (sec >= s->window) {
    s->count = 0;
    s->t0.tv_sec = t1.tv_sec;
    s->t0.tv_nsec = 0;
  }

  VERBOSE(s, 3, "INTERVAL:%d/%d\n", sec, s->window);

  s->count++;

  if ((s->limit > 0) && (s->count > s->limit)) {
    VERBOSE(s, 2, "DISCARD:%zu/%zu:%s", s->count, s->limit, buf);
    return buflen;
  }

  return fwrite(buf, 1, buflen, stdout);
}

static void usage() {
  (void)fprintf(stderr,
                "%s: [OPTION]\n"
                "Pressure relief valve, version: %s (using %s mode process "
                "restriction)\n\n"
                "-l, --limit               message rate limit\n"
                "-w, --window              message rate window\n"
                "-W, --write-error <exit|drop|block>\n"
                "                          behaviour if write buffer is full\n"
                "-v, --verbose             verbose mode\n"
                "-h, --help                help\n",
                __progname, PRV_VERSION, RESTRICT_PROCESS);
}
