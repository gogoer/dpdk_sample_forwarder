#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>

int parse_ip_list(const char *ips_list, uint32_t *ip_array, int max_ips);

#endif
