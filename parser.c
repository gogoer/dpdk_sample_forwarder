#include "parser.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int parse_ip_list(const char *ips_list, uint32_t *ip_array, int max_ips)
{
    if (!ips_list || !ip_array || max_ips <= 0)
        return 0;

    char ips_copy[1024];
    strncpy(ips_copy, ips_list, sizeof(ips_copy) - 1);
    ips_copy[sizeof(ips_copy) - 1] = '\0';

    int count = 0;
    char *token = strtok(ips_copy, ",");

    while (token != NULL && count < max_ips) {
        struct in_addr addr;
        if (inet_pton(AF_INET, token, &addr) != 1) {
            printf("wrong IP: %s\n", token);
        } else {
            ip_array[count++] = addr.s_addr;
        }
        token = strtok(NULL, ",");
    }

    return count;
}
