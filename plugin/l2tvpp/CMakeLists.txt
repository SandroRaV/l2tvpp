# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
# Build as an out-of-tree VPP plugin, or drop into src/plugins/l2tvpp/
add_vpp_plugin(l2tvpp
  SOURCES
  l2tvpp.c
  l2tvpp_api.c
  l2tvpp_cli.c
  node.c

  API_FILES
  l2tvpp.api

  INSTALL_HEADERS
  l2tvpp.h
)
