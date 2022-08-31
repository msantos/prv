/*	$NetBSD: getline.c,v 1.1.1.6 2015/01/02 20:34:27 christos Exp $	*/

/*	NetBSD: getline.c,v 1.2 2014/09/16 17:23:50 christos Exp 	*/

/*-
 * Copyright (c) 2011 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* openssh-portable:
 * https://raw.githubusercontent.com/openssh/openssh-portable/872517ddbb72deaff31d4760f28f2b0a1c16358f/openbsd-compat/bsd-getline.c
 */
/* NETBSD ORIGINAL: external/bsd/file/dist/src/getline.c */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ssize_t getndelim(char **buf, size_t *bufsiz, size_t nmax, int delimiter,
                  FILE *fp) {
  char *ptr, *eptr;

  if (*buf == NULL || *bufsiz == 0) {
    if ((*buf = malloc(BUFSIZ)) == NULL)
      return -1;
    *bufsiz = BUFSIZ;
  }

  for (ptr = *buf, eptr = *buf + *bufsiz;;) {
    int c = fgetc(fp);
    if (c == -1) {
      if (feof(fp)) {
        ssize_t diff = (ssize_t)(ptr - *buf);
        if (diff != 0) {
          *ptr = '\0';
          return diff;
        }
      }
      return -1;
    }
    *ptr++ = c;
    if (c == delimiter || ptr - *buf >= nmax) {
      *ptr = '\0';
      return ptr - *buf;
    }
    if (ptr + 2 >= eptr) {
      char *nbuf;
      size_t nbufsiz = *bufsiz * 2;
      ssize_t d = ptr - *buf;
      if ((nbuf = realloc(*buf, nbufsiz)) == NULL)
        return -1;
      *buf = nbuf;
      *bufsiz = nbufsiz;
      eptr = nbuf + nbufsiz;
      ptr = nbuf + d;
    }
  }
}

ssize_t getnline(char **buf, size_t *bufsiz, size_t nmax, FILE *fp) {
  return getndelim(buf, bufsiz, nmax, '\n', fp);
}
