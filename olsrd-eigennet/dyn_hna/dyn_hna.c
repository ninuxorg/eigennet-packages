/*
* The olsr.org Optimized Link-State Routing daemon(olsrd)
* Copyright (c) 2004-2009, the olsr.org team - see HISTORY file
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* * Redistributions of source code must retain the above copyright
*  notice, this list of conditions and the following disclaimer.
* * Redistributions in binary form must reproduce the above copyright
*  notice, this list of conditions and the following disclaimer in
*  the documentation and/or other materials provided with the
*  distribution.
* * Neither the name of olsr.org, olsrd nor the names of its
*  contributors may be used to endorse or promote products derived
*  from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
* COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
* ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Visit http://www.olsr.org for more information.
*
* If you find this software useful feel free to make a donation
* to the project. For more information see the website or contact
* the copyright holders.
*
*/

/* System includes */
#include <assert.h>            /* assert() */
#include <stddef.h>            /* NULL */
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>




/* OLSRD includes */
#include "plugin.h"
#include "plugin_util.h"
#include "defs.h"              /* uint8_t, olsr_cnf */
#include "scheduler.h"          /* olsr_start_timer() */
#include "olsr_cfg.h"          /* olsr_cnf() */
#include "olsr_cookie.h"        /* olsr_alloc_cookie() */
#define PLUGIN_INTERFACE_VERSION 5



static void olsr_event1(void *foo __attribute__ ((unused)) );
static struct olsr_cookie_info *event_timer_cookie1;


/**
* Plugin interface version
* Used by main olsrd to check plugin interface version
*/
int olsrd_plugin_interface_version(void) {
  return PLUGIN_INTERFACE_VERSION;
}



void olsrd_get_plugin_parameters(const struct olsrd_plugin_parameters **params __attribute__ ((unused)), int *size __attribute__ ((unused))) {
}


int
olsrd_plugin_init(void)
{




  event_timer_cookie1 = olsr_alloc_cookie("Processing pipe", OLSR_COOKIE_TYPE_TIMER);

  olsr_start_timer(5 * MSEC_PER_SEC, 0, OLSR_TIMER_PERIODIC, &olsr_event1, NULL, event_timer_cookie1);


//custom init code

return 1;

}



static void olsr_event1(void *foo __attribute__ ((unused)) ) {
    
// Do things every 5 seconds

}

 
