/*
** Copyright (C) 2009-2017 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2017 Adam Hall <ahall@quadrantsec.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* sagan-check-flow.c */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#include "sagan.h"
#include "sagan-defs.h"
#include "sagan-rules.h"
#include "sagan-config.h"

struct _Rule_Struct *rulestruct;

/********************/ /************************/ /*****************/
/***** flow_type ****/ /******* flow_var *******/ /*** direction ***/
/* 0 = not in group */ /**      0 = any       **/ /**   0 = any   **/
/* 1 = in group     */ /**      1 = var       **/ /**  1 = right  **/
/* 2 = not match ip */ /************************/ /**   2 = left  **/
/* 3 = match ip     */ /************************/ /*****************/
/********************/ /************************/ /*****************/

sbool Sagan_Check_Flow( int b, uint32_t ip_src_u32, uint32_t ip_dst_u32)
{

    uint32_t *src;
    uint32_t *dst;

    uint32_t ip_src;
    uint32_t ip_dst;

    src = &ip_src_u32;
    dst = &ip_dst_u32;

    if(rulestruct[b].direction == 0 || rulestruct[b].direction == 1) {
        ip_src = *src;
        ip_dst = *dst;
    } else {
        ip_src = *dst;
        ip_dst = *src;
    }

    /*flow 1*/
    int w=0;
    int a1=0;
    int eq1=0;
    int ne1=0;
    int eq1_val=0;
    int ne1_val=0;
//    char *tmptoken1;
//    char *saveptrflow1;
//    char *tmp1;
//    char tmp_flow_1[512];
    int f1;

    /*flow 2*/
    int z=0;
    int a2=0;
    int eq2=0;
    int ne2=0;
    int eq2_val=0;
    int ne2_val=0;
//    char *tmptoken2;
//    char *saveptrflow2;
//    char *tmp2;
//    char tmp_flow_2[512];
    int f2;

//    uint32_t lo;
//    uint32_t hi;

    int i;
    int failed=0;

    /*Begin flow_1*/
    if(rulestruct[b].flow_1_var != 0) {
        for(i=0; i < rulestruct[b].flow_1_counter + 1; i++) {
            w++;
            f1 = rulestruct[b].flow_1_type[w];

            if(f1 == 0) {
                ne1++;
                if(ip_src > rulestruct[b].flow_1[i].lo && ip_src < rulestruct[b].flow_1[i].hi) {
                    ne1_val++;
                }
            } else if(f1 == 1) {
                eq1++;
                if(ip_src > rulestruct[b].flow_1[i].lo && ip_src < rulestruct[b].flow_1[i].hi) {
                    eq1_val++;
                }
            } else if(f1 == 2) {
                ne1++;
                if(ip_src == rulestruct[b].flow_1[i].lo ) {
                    ne1_val++;
                }
            } else if(f1 == 3) {
                eq1++;
                if(ip_src == rulestruct[b].flow_1[i].lo ) {
                    eq1_val++;
                }
            }
        }
    } else {
        a1=1;
    }

    /* if ne1, did anything match (meaning failed) */
    if(ne1>0) {
        if(ne1_val > 0) {
            failed++;
        }
    }

    /* if eq1, did anything not match meaning failed */
    if(eq1>0) {
        if(eq1_val < 1) {
            failed++;
        }
    }

    /* if either failed, we did not match, no need to check the second flow... we already failed! */
    if(a1 != 1) {
        if(failed > 0) {
            return 0;
        }
    }

    /*Begin flow_2*/
    if(rulestruct[b].flow_2_var != 0) {
        for(i=0; i < rulestruct[b].flow_2_counter + 1; i++) {
            z++;
            f2 = rulestruct[b].flow_2_type[z];

            if(f2 == 0) {
                ne2++;
                if(ip_dst > rulestruct[b].flow_2[i].lo && ip_dst < rulestruct[b].flow_2[i].hi) {
                    ne2_val++;
                }
            } else if(f2 == 1) {
                eq2++;
                if(ip_dst > rulestruct[b].flow_2[i].lo && ip_dst < rulestruct[b].flow_2[i].hi) {
                    eq2_val++;
                }
            } else if(f2 == 2) {
                ne2++;
                if(ip_dst == rulestruct[b].flow_2[i].lo) {
                    ne2_val++;
                }
            } else if(f2 == 3) {
                eq2++;
                if(ip_dst == rulestruct[b].flow_2[i].lo) {
                    eq2_val++;
                }
            }
        }
    } else {
        a2=1;
    }

    /* if ne2, did anything match (meaning failed) */
    if(ne2>0) {
        if(ne2_val > 0) {
            failed++;
        }
    }

    /* if eq2, did anything not match meaning failed */
    if(eq2>0) {
        if(eq2_val < 1) {
            failed++;
        }
    }

    /* if either failed, we did not match, leave */
    if(a2 != 1) {
        if(failed > 0) {
            return 0;
        }
    }

    /* If we made it to this point we have a match */
    return 1;

}/*We are done*/
