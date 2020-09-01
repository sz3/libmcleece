
#include <string.h>
#include "helpers.h"

void
trim(char *str)
{
	size_t i = strlen(str);

	while (i-- > (size_t) 0U) {
		if (str[i] == '\n' || str[i] == '\r') {
			str[i] = 0;
		}
	}
}
