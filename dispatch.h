/**
 * dispatch.h — Command dispatch
 *
 * Routes parsed configuration to the appropriate command handler
 * (analyze or capture).
 */
#ifndef DISPATCH_H
#define DISPATCH_H

#include "mmt_core.h"
#include "argparse.h"

/**
 * Dispatch to the appropriate command based on config.
 * @param cfg    parsed configuration
 * @return 0 on success, 1 on error
 */
int dispatch(const mmt_config_t *cfg);

#endif /* DISPATCH_H */
