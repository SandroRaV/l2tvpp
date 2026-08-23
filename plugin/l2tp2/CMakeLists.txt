# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
# Build as an out-of-tree VPP plugin, or drop into src/plugins/l2tp2/
add_vpp_plugin(l2tp2
  SOURCES
  l2tp2.c
  l2tp2_api.c
  l2tp2_cli.c
  node.c
  encap.c

  API_FILES
  l2tp2.api

  INSTALL_HEADERS
  l2tp2.h
)
