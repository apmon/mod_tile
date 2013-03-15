/* wrapper for storage engines
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "store.h"
#include "store_file.h"

struct storage_backend * init_storage_backend(const char * options) {
    struct storage_backend * store = init_storage_file(options);
    return store;
}
