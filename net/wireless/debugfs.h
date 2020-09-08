/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CFG80211_DEBUGFS_H
#define __CFG80211_DEBUGFS_H

#ifdef CPTCFG_CFG80211_DEBUGFS
void cyw_cfg80211_debugfs_rdev_add(struct cyw_cfg80211_registered_device *rdev);
#else
static inline
void cyw_cfg80211_debugfs_rdev_add(struct cyw_cfg80211_registered_device *rdev) {}
#endif

#endif /* __CFG80211_DEBUGFS_H */
