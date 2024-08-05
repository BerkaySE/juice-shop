/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/**
 * This script starts by validating dependencies at startup and then launches the server.
 * The server module encapsulates the details of the server (like server type, route configurations, etc).
 * No parameters are taken in since the server and startup details are abstracted away in their corresponding modules.
 * Returns : It does not explicitly return a value. Its purpose is primarily an entry point to kickstart the server.
 */
require('./lib/startup/validateDependencies')().then(() => {
  const server = require('./server')
  server.start()
})
