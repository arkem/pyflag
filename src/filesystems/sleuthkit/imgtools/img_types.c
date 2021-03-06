/*
** img_types
** The Sleuth Kit 
**
** $Date: 2007/04/04 20:06:58 $
**
** Identify the type of image file being used
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2006 Brian Carrier.  All rights reserved 
**
** This software is distributed under the Common Public License 1.0
*/

#include "img_tools.h"

typedef struct {
    char *name;
    uint8_t code;
    char *comment;
} IMG_TYPES;

/* The table used to parse input strings 
 * - in order of expected usage
 */
IMG_TYPES img_open_table[] = {
    {"raw", TSK_IMG_INFO_TYPE_RAW_SING, "raw (dd)"},
#ifdef USE_LIBAFF
    {"aff", TSK_IMG_INFO_TYPE_AFF_AFF, "Advanced Forensic Format"},
    {"afd", TSK_IMG_INFO_TYPE_AFF_AFD, "AFF Multiple File"},
    {"afm", TSK_IMG_INFO_TYPE_AFF_AFM, "AFF with external metadata"},
#endif
#ifdef USE_LIBEWF
    {"ewf", TSK_IMG_INFO_TYPE_EWF_EWF, "Expert Witness format (encase)"},
#endif
    {"split", TSK_IMG_INFO_TYPE_RAW_SPLIT, "Split raw files"},
    {0},
};


TSK_IMG_INFO_TYPE_ENUM
tsk_img_parse_type(const TSK_TCHAR * str)
{
    char tmp[16];
    IMG_TYPES *sp;
    int i;
    // convert to char
    for (i = 0; i < 15 && str[i] != '\0'; i++) {
        tmp[i] = (char) str[i];
    }
    tmp[i] = '\0';

    for (sp = img_open_table; sp->name; sp++) {
        if (strcmp(tmp, sp->name) == 0) {
            return sp->code;
        }
    }
    return TSK_IMG_INFO_TYPE_UNSUPP;
}


/* Used by the usage functions to display supported types */
void
tsk_img_print_types(FILE * hFile)
{
    IMG_TYPES *sp;
    tsk_fprintf(hFile, "Supported image format types:\n");
    for (sp = img_open_table; sp->name; sp++)
        tsk_fprintf(hFile, "\t%s (%s)\n", sp->name, sp->comment);
}

char *
tsk_img_get_type(TSK_IMG_INFO_TYPE_ENUM ftype)
{
    IMG_TYPES *sp;
    for (sp = img_open_table; sp->name; sp++)
        if (sp->code == ftype)
            return sp->name;

    return NULL;
}
