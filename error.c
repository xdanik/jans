/* released under GPLv2 by folkert@vanheusden.com */
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

void error_exit(const char *format, ...)
{
	int err_nr = errno;
        char buffer[4096];
        va_list ap;

        va_start(ap, format);
        vsnprintf(buffer, sizeof(buffer), format, ap);
        va_end(ap);

        fprintf(stderr, "FATAL error: %s\n", buffer);
	fprintf(stderr, "errno (if applicable): %d / %s\n", err_nr, strerror(err_nr));

        exit(EXIT_FAILURE);
}
