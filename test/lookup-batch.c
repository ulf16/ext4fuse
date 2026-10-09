/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "disk.h"
#include "inode.h"
#include "logging.h"
int main(int argc,char **argv)
{
    if (argc!=4 || logging_open("/dev/null")<0 || disk_open(argv[1])<0 ||
        super_fill()<0 || super_group_fill()<0 || inode_init()<0) return 2;
    FILE *input=fopen(argv[3],"r");if (!input) return 2;
    char *line=NULL;size_t capacity=0;ssize_t length;
    while ((length=getline(&line,&capacity,input))>=0) {
        if (length && line[length-1]=='\n') line[--length]=0;
        char path[1024];if (snprintf(path,sizeof(path),"%s/%s",argv[2],line)>=(int)sizeof(path)) return 2;
        uint32_t number=0;int ret=inode_lookup(path,&number);
        printf("%d %u\n",ret,number);
    }
    free(line);fclose(input);return 0;
}
