/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <openthread-core-config.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openthread/config.h>

#include <openthread/cli.h>
#include <openthread/diag.h>
#include <openthread/tasklet.h>
#include <openthread/platform/logging.h>

#include "openthread-system.h"
#include "cli/cli_config.h"
#include "common/code_utils.hpp"

#include "lib/platform/reset_util.h"

/**
 * This function initializes the CLI app.
 *
 * @param[in]  aInstance  The OpenThread instance structure.
 *
 */
extern void otAppCliInit(otInstance *aInstance);

#if OPENTHREAD_CONFIG_HEAP_EXTERNAL_ENABLE
OT_TOOL_WEAK void *otPlatCAlloc(size_t aNum, size_t aSize)
{
    return calloc(aNum, aSize);
}

OT_TOOL_WEAK void otPlatFree(void *aPtr)
{
    free(aPtr);
}
#endif

void otTaskletsSignalPending(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);
}

#if OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static otError ProcessExit(void *aContext, uint8_t aArgsLength, char *aArgs[])
{
    OT_UNUSED_VARIABLE(aContext);
    OT_UNUSED_VARIABLE(aArgsLength);
    OT_UNUSED_VARIABLE(aArgs);

    exit(EXIT_SUCCESS);
}

#if OPENTHREAD_EXAMPLES_SIMULATION
extern otError ProcessNodeIdFilter(void *aContext, uint8_t aArgsLength, char *aArgs[]);
#endif

static const otCliCommand kCommands[] = {
    {"exit", ProcessExit},
#if OPENTHREAD_EXAMPLES_SIMULATION
    /*
     * The CLI command `nodeidfilter` only works for simulation in real time.
     * The usage of the command `nodeidfilter`:
     *     - `nodeidfilter deny <nodeid>`:  It denies the connection to a specified node.
     *     - `nodeidfilter clear`:          It restores the filter state to default.
     */
    {"nodeidfilter", ProcessNodeIdFilter},
#endif
};
#endif // OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)

struct log_event {
  uint32_t timePoweredUp;
  uint32_t moduleId;
  uint8_t moduleEventId;
};

struct log_data_event {
  uint32_t timePoweredUp;
  uint8_t moduleId;
  uint8_t moduleEventId;
  uint8_t eventDataLength;
  uint8_t eventData[9];
};

void parse_data(FILE* file) {
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), file)) {
    char* token;
    token = strtok(buffer, " \n");
    printf("=====================================\n");
    printf("token: \"%s\"\n", token);
    printf("=====================================\n");
    if (!strcmp(token, "\"Brief\":")) {
      continue;
    }
    if (!strcmp(token, "\"Name\":")) {
      token = strtok(NULL, " ");
      printf("Name: %s\n", token);
    }
    if (!strcmp(token, "\"Type\":")) {
      token = strtok(NULL, " ");
      printf("Type: %s\n", token);
    }
  }
}

void parse_module(FILE* file) {
  printf("in parse_module\n");
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), file)) {
    char* token;
    token = strtok(buffer, " ");
    if (!strcmp(token, "\"Brief\":")) {
      continue;
    }
    if (!strcmp(token, "\"Name\":")) {
      token = strtok(NULL, " ");
      printf("Name: %s\n", token);
    }
    if (!strcmp(token, "\"Value\":")) {
      token = strtok(NULL, " ");
      printf("Value: %ld\n", strtol(token, NULL, 10));
    }
    if (!strcmp(token, "\"DataLength\":")) {
      token = strtok(NULL, " ");
      printf("DataLength: %ld\n", strtol(token, NULL, 10));
    }
    if (!strcmp(token, "\"Data\":")) {
      token = strtok(NULL, " ,");
      if (strcmp(token, "null")) {
        parse_data(file);
      }
    }
    if (!strcmp(token, "\"SaveToNvMem\":")) {
      token = strtok(NULL, " ");
      printf("SaveToNvMem: %s\n", token);
    }
    if (!strcmp(token, "\"Type\":")) {
      token = strtok(NULL, " ");
      printf("Type: %s\n", token);
    }
    if (!strcmp(token, "]")) {
      printf("hit ]\n");
    }
  }
}

void parse_modules(FILE* file) {
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), file)) {
    char* token;
    token = strtok(buffer, " ");
    if (!strcmp(token, "\"ModuleEvents\":")) {
      parse_module(file);
      break;
    }
    if (!strcmp(token, "\"Brief\":")) {
      continue;
    }
    if (!strcmp(token, "\"ModuleName\":")) {
      token = strtok(NULL, " ");
      printf("Module name: %s\n", token);
    }
    if (!strcmp(token, "\"Value\":")) {
      token = strtok(NULL, " ");
      printf("Module Value: %ld\n", strtol(token, NULL, 10));
    }
  }
}

int read_file(const char *path) {
  FILE* file;
  file = fopen(path, "r");
  if (file == NULL) {
    perror("read_file::fopen()");
    return -1;
  }

  char buffer[256];
  int start = 0;
  int curr = 0;
  int max = 0;
  while (fgets(buffer, sizeof(buffer), file)) {
    //// getting max line len, 230
    //curr = ftell(file);
    //max = max > (curr - start) ? max : (curr - start);
    //start = curr;

    char* token;
    token = strtok(buffer, " ");
    if (!strcmp(token, "\"Modules\":")) {
      printf("modules\n");
      parse_modules(file);
      break;
    }
  }

  if (ferror(file)) {
    perror("read_file::fgets()");
    clearerr(file);
  }
  fclose(file);
  //printf("max buf len: %d\n", max);
}

int main(int argc, char *argv[])
{
  printf("hey\n");
  read_file("/home/nathaniel/event-structure-and-definition.txt");


    otInstance *instance;

    OT_SETUP_RESET_JUMP(argv);

#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    size_t   otInstanceBufferLength = 0;
    uint8_t *otInstanceBuffer       = NULL;
#endif

pseudo_reset:

    otSysInit(argc, argv);

#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    // Call to query the buffer size
    (void)otInstanceInit(NULL, &otInstanceBufferLength);

    // Call to allocate the buffer
    otInstanceBuffer = (uint8_t *)malloc(otInstanceBufferLength);
    assert(otInstanceBuffer);

    // Initialize OpenThread with the buffer
    instance = otInstanceInit(otInstanceBuffer, &otInstanceBufferLength);
#else
    instance = otInstanceInitSingle();
#endif
    assert(instance);

    otAppCliInit(instance);

#if OPENTHREAD_POSIX && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    otCliSetUserCommands(kCommands, OT_ARRAY_LENGTH(kCommands), instance);
#endif

    while (!otSysPseudoResetWasRequested())
    {
        otTaskletsProcess(instance);
        otSysProcessDrivers(instance);
    }

    otInstanceFinalize(instance);
#if OPENTHREAD_CONFIG_MULTIPLE_INSTANCE_ENABLE
    free(otInstanceBuffer);
#endif

    goto pseudo_reset;

    return 0;
}

#if OPENTHREAD_CONFIG_LOG_OUTPUT == OPENTHREAD_CONFIG_LOG_OUTPUT_APP
void otPlatLog(otLogLevel aLogLevel, otLogRegion aLogRegion, const char *aFormat, ...)
{
    va_list ap;

    va_start(ap, aFormat);
    otCliPlatLogv(aLogLevel, aLogRegion, aFormat, ap);
    va_end(ap);
}
#endif
