#include <stdio.h>
#include <stdlib.h>

#include "traceroute.h"

int main(int argc, char * argv[])
{
    const char * host = "www.baidu.com";

    switch(argc)
    {
        case 1:
            break;
        case 2:
            host = argv[1];
            break;
        default:
            return -1;
            break;
    }

    char * res = traceroute_report(host);
    if (res != NULL)
    {
        printf("result: %s\n", res);
        free(res);
        res = NULL;
    }

    return 0;
}