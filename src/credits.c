/*
** Copyright (C) 2009-2020 Quadrant Information Security <quadrantsec.com>
** Copyright (C) 2009-2020 Champ Clark III <cclark@quadrantsec.com>
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

/* credit.c
 *
 * Give credit where credit is due
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"             /* From autoconf */
#endif

#include "sagan.h"
#include "version.h"

void Credits(void)
{

    fprintf(stderr, "\n--[Sagan version %s | Credits]--------------------------------\n\n", VERSION);
    fprintf(stderr, "Champ Clark III (cclark@quadrantsec.com)\tLead developer.\n");
    fprintf(stderr, "Robert Nunley (rnunley@quadrantsec.com)\t\tRules/Ideas.\n");
    fprintf(stderr, "Brian Echeverry (becheverry@quadrantsec.com)\tRules/testing/bug report.\n");
    fprintf(stderr, "Marcus Ranum\t\t\t\t\tplog.c code.\n");
    fprintf(stderr, "\"DrForbin\"\t\t\t\t\tPatches/testing/bug fixes.\n");
    fprintf(stderr, "Rainer Gerhards\t\t\t\t\tRsyslog/Liblognorm author.\n");
    fprintf(stderr, "Bruce M. Wink (bwink@quadrantsec.com)\t\tIdeas.\n");
    fprintf(stderr, "Daniel Koopmans\t\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"remydb\" (Github)\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"CyberTaoFlow\" (Github)\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"nix8\" (Github)\t\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"pitrpitr\" (Github)\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"ebayer\" (Github)\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"Juan Manuel (jmcabo - Github)\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"Stas Alekseev\" (salekseev - Github)\t\tSpec file for Redhat/Fedora.\n");
    fprintf(stderr, "\"Alice Kaerast\" (kaerast - Github\t\trsyslog example in 'extra'.\n");
    fprintf(stderr, "\"DigiAngel\" (Github)\t\t\t\t'content:!' idea.\n");
    fprintf(stderr, "Robert Bridge (RobbieAB - Github)\t\t'flowbit/xbit' idea.\n");
    fprintf(stderr, "Mathieu Parent (sathieu - Github)\t\tOld MySQL port fix.\n");
    fprintf(stderr, "Pierre Chifflier (chifflier - Github)\t\tPatches/bug fixes/man page.\n");
    fprintf(stderr, "Pierre Chifflier \t\t\t\tDebian/Ubuntu packages.\n");
    fprintf(stderr, "\"miverson\" (Github)\t\t\t\tOSSEC converter/bug fixes.\n");
    fprintf(stderr, "\"ekse\" (Github)\t\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"mtgxx\" (Github)\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "\"powertoaster\" (Github)\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "Pawel Hajdan jr (Gentoo)\t\t\tGentoo ebuild.\n");
    fprintf(stderr, "James Lay\t\t\t\t\tRules.\n");
    fprintf(stderr, "Brad Doctor\t\t\t\t\tRules.\n");
    fprintf(stderr, "Sniffty Dugen\t\t\t\t\tRules.\n");
    fprintf(stderr, "Iman Khosravi\t\t\t\t\tRules.\n");
    fprintf(stderr, "Jon Schipp\t\t\t\t\tBug reports & testing.\n");
    fprintf(stderr, "Aleksey Chudov\t\t\t\t\t\"logrotate\" fix/suggestion.\n");
    fprintf(stderr, "DonPiekarz (Github)\t\t\t\tBug reports & fixes.\n");
    fprintf(stderr, "rtkkdeng (Github)\t\t\t\tRules fixes.\n");
    fprintf(stderr, "Adam Hall\t\t\t\t\tAetas & other bug fixes.\n");
    fprintf(stderr, "Bruno Coudoin (Github:bdoin)\t\t\tBug fixes.\n");
    fprintf(stderr, "Nuno Fernandes (Github)\t\t\t\tBug fixes & rule corrections.\n");
    fprintf(stderr, "Alexandre Carrol Perales (Github:acabrol)\tBug fixes & features.\n");
    fprintf(stderr, "Bruno Coudoin\t\t\t\t\tBug fixes & features.\n");
    fprintf(stderr, "Steve Rawls (srawls@quadrantsec.com)\t\tBug reports & features.\n");
    fprintf(stderr, "\"bhennigar\" (Github)\t\t\t\tBug reporting & testing.\n");
    fprintf(stderr, "Corey Fisher (cfisher@quadrantsec.com)\t\tCode testing & debugging.\n");
    fprintf(stderr, "\"Work-lako\" (Github)\t\t\t\tIdea/patch for syslog-handler.c.\n");
    fprintf(stderr, "Jeremy A. Grove (jgrove@quadrantsec.com)\tBug reporting.\n");
    fprintf(stderr, "Ray Ruvinskiy (Github: rtkrruvinskiy)\t\tDaemonization Fixes.\n");
    fprintf(stderr, "\"YoichSec\" (Github) (Yoichi Sagawa)\t\tXbit track by src/dst port code.\n");
    fprintf(stderr, "\"YoichSec\" (Github)\t\t\t\tChanging rules to match Suricata/Snort.\n");
    fprintf(stderr, "\"3vilJohn\" (Twitter)\t\t\t\tVarious bug reports & testing.\n");
    fprintf(stderr, "Kenneth Shelton (@netwatcher)\t\t\tIPv6 support, bug fixes.\n");
    fprintf(stderr, "Brian Candler (@candlerb)\t\t\tLots of bug fixes, enchancements, improvements.");

    fprintf(stderr, "\n");

}


