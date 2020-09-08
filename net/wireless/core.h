/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wireless configuration interface internals.
 *
 * Copyright 2006-2010	Johannes Berg <johannes@sipsolutions.net>
 * Copyright (C) 2018-2019 Intel Corporation
 */
#ifndef __NET_WIRELESS_CORE_H
#define __NET_WIRELESS_CORE_H
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rbtree.h>
#include <linux/debugfs.h>
#include <linux/rfkill.h>
#include <linux/workqueue.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <net/cyw_cfg80211.h>
#include "reg.h"


#define WIPHY_IDX_INVALID	-1

struct cyw_cfg80211_registered_device {
	const struct cyw_cfg80211_ops *ops;
	struct list_head list;

	/* rfkill support */
	struct rfkill_ops rfkill_ops;
	struct rfkill *rfkill;
	struct work_struct rfkill_block;

	/* ISO / IEC 3166 alpha2 for which this device is receiving
	 * country IEs on, this can help disregard country IEs from APs
	 * on the same alpha2 quickly. The alpha2 may differ from
	 * cyw_cfg80211_regdomain's alpha2 when an intersection has occurred.
	 * If the AP is reconfigured this can also be used to tell us if
	 * the country on the country IE changed. */
	char country_ie_alpha2[2];

	/*
	 * the driver requests the regulatory core to set this regulatory
	 * domain as the wiphy's. Only used for %REGULATORY_WIPHY_SELF_MANAGED
	 * devices using the regulatory_set_wiphy_regd() API
	 */
	const struct ieee80211_regdomain *requested_regd;

	/* If a Country IE has been received this tells us the environment
	 * which its telling us its in. This defaults to ENVIRON_ANY */
	enum environment_cap env;

	/* wiphy index, internal only */
	int wiphy_idx;

	/* protected by RTNL */
	int devlist_generation, wdev_id;
	int opencount;
	wait_queue_head_t dev_wait;

	struct list_head beacon_registrations;
	spinlock_t beacon_registrations_lock;

	struct list_head mlme_unreg;
	spinlock_t mlme_unreg_lock;
	struct work_struct mlme_unreg_wk;

	/* protected by RTNL only */
	int num_running_ifaces;
	int num_running_monitor_ifaces;
	u64 cookie_counter;

	/* BSSes/scanning */
	spinlock_t bss_lock;
	struct list_head bss_list;
	struct rb_root bss_tree;
	u32 bss_generation;
	u32 bss_entries;
	struct cyw_cfg80211_scan_request *scan_req; /* protected by RTNL */
	struct sk_buff *scan_msg;
	struct list_head sched_scan_req_list;
	unsigned long suspend_at;
	struct work_struct scan_done_wk;

	struct genl_info *cur_cmd_info;

	struct work_struct conn_work;
	struct work_struct event_work;

	struct delayed_work dfs_update_channels_wk;

	/* netlink port which started critical protocol (0 means not started) */
	u32 crit_proto_nlportid;

	struct cyw_cfg80211_coalesce *coalesce;

	struct work_struct destroy_work;
	struct work_struct sched_scan_stop_wk;
	struct work_struct sched_scan_res_wk;

	struct cyw_cfg80211_chan_def radar_chandef;
	struct work_struct propagate_radar_detect_wk;

	struct cyw_cfg80211_chan_def cac_done_chandef;
	struct work_struct propagate_cac_done_wk;

	/* must be last because of the way we do wiphy_priv(),
	 * and it should at least be aligned to NETDEV_ALIGN */
	struct wiphy wiphy __aligned(NETDEV_ALIGN);
};

static inline
struct cyw_cfg80211_registered_device *wiphy_to_rdev(struct wiphy *wiphy)
{
	BUG_ON(!wiphy);
	return container_of(wiphy, struct cyw_cfg80211_registered_device, wiphy);
}

static inline void
cyw_cfg80211_rdev_free_wowlan(struct cyw_cfg80211_registered_device *rdev)
{
#ifdef CONFIG_PM
	int i;

	if (!rdev->wiphy.wowlan_config)
		return;
	for (i = 0; i < rdev->wiphy.wowlan_config->n_patterns; i++)
		kfree(rdev->wiphy.wowlan_config->patterns[i].mask);
	kfree(rdev->wiphy.wowlan_config->patterns);
	if (rdev->wiphy.wowlan_config->tcp &&
	    rdev->wiphy.wowlan_config->tcp->sock)
		sock_release(rdev->wiphy.wowlan_config->tcp->sock);
	kfree(rdev->wiphy.wowlan_config->tcp);
	kfree(rdev->wiphy.wowlan_config->nd_config);
	kfree(rdev->wiphy.wowlan_config);
#endif
}

static inline u64 cyw_cfg80211_assign_cookie(struct cyw_cfg80211_registered_device *rdev)
{
	u64 r = ++rdev->cookie_counter;

	if (WARN_ON(r == 0))
		r = ++rdev->cookie_counter;

	return r;
}

extern struct workqueue_struct *cyw_cfg80211_wq;
extern struct list_head cyw_cfg80211_rdev_list;
extern int cyw_cfg80211_rdev_list_generation;

struct cyw_cfg80211_internal_bss {
	struct list_head list;
	struct list_head hidden_list;
	struct rb_node rbn;
	u64 ts_boottime;
	unsigned long ts;
	unsigned long refcount;
	atomic_t hold;

	/* time at the start of the reception of the first octet of the
	 * timestamp field of the last beacon/probe received for this BSS.
	 * The time is the TSF of the BSS specified by %parent_bssid.
	 */
	u64 parent_tsf;

	/* the BSS according to which %parent_tsf is set. This is set to
	 * the BSS that the interface that requested the scan was connected to
	 * when the beacon/probe was received.
	 */
	u8 parent_bssid[ETH_ALEN] __aligned(2);

	/* must be last because of priv member */
	struct cyw_cfg80211_bss pub;
};

static inline struct cyw_cfg80211_internal_bss *bss_from_pub(struct cyw_cfg80211_bss *pub)
{
	return container_of(pub, struct cyw_cfg80211_internal_bss, pub);
}

static inline void cyw_cfg80211_hold_bss(struct cyw_cfg80211_internal_bss *bss)
{
	atomic_inc(&bss->hold);
	if (bss->pub.transmitted_bss) {
		bss = container_of(bss->pub.transmitted_bss,
				   struct cyw_cfg80211_internal_bss, pub);
		atomic_inc(&bss->hold);
	}
}

static inline void cyw_cfg80211_unhold_bss(struct cyw_cfg80211_internal_bss *bss)
{
	int r = atomic_dec_return(&bss->hold);
	WARN_ON(r < 0);
	if (bss->pub.transmitted_bss) {
		bss = container_of(bss->pub.transmitted_bss,
				   struct cyw_cfg80211_internal_bss, pub);
		r = atomic_dec_return(&bss->hold);
		WARN_ON(r < 0);
	}
}


struct cyw_cfg80211_registered_device *cyw_cfg80211_rdev_by_wiphy_idx(int wiphy_idx);
int get_wiphy_idx(struct wiphy *wiphy);

struct wiphy *wiphy_idx_to_wiphy(int wiphy_idx);

int cyw_cfg80211_switch_netns(struct cyw_cfg80211_registered_device *rdev,
			  struct net *net);

void cyw_cfg80211_init_wdev(struct cyw_cfg80211_registered_device *rdev,
			struct wireless_dev *wdev);

static inline void wdev_lock(struct wireless_dev *wdev)
	__acquires(wdev)
{
	mutex_lock(&wdev->mtx);
	__acquire(wdev->mtx);
}

static inline void wdev_unlock(struct wireless_dev *wdev)
	__releases(wdev)
{
	__release(wdev->mtx);
	mutex_unlock(&wdev->mtx);
}

#define ASSERT_WDEV_LOCK(wdev) lockdep_assert_held(&(wdev)->mtx)

static inline bool cyw_cfg80211_has_monitors_only(struct cyw_cfg80211_registered_device *rdev)
{
	ASSERT_RTNL();

	return rdev->num_running_ifaces == rdev->num_running_monitor_ifaces &&
	       rdev->num_running_ifaces > 0;
}

enum cyw_cfg80211_event_type {
	EVENT_CONNECT_RESULT,
	EVENT_ROAMED,
	EVENT_DISCONNECTED,
	EVENT_IBSS_JOINED,
	EVENT_STOPPED,
	EVENT_PORT_AUTHORIZED,
};

struct cyw_cfg80211_event {
	struct list_head list;
	enum cyw_cfg80211_event_type type;

	union {
		struct cyw_cfg80211_connect_resp_params cr;
		struct cyw_cfg80211_roam_info rm;
		struct {
			const u8 *ie;
			size_t ie_len;
			u16 reason;
			bool locally_generated;
		} dc;
		struct {
			u8 bssid[ETH_ALEN];
			struct ieee80211_channel *channel;
		} ij;
		struct {
			u8 bssid[ETH_ALEN];
		} pa;
	};
};

struct cyw_cfg80211_cached_keys {
	struct key_params params[CFG80211_MAX_WEP_KEYS];
	u8 data[CFG80211_MAX_WEP_KEYS][WLAN_KEY_LEN_WEP104];
	int def;
};

enum cyw_cfg80211_chan_mode {
	CHAN_MODE_UNDEFINED,
	CHAN_MODE_SHARED,
	CHAN_MODE_EXCLUSIVE,
};

struct cyw_cfg80211_beacon_registration {
	struct list_head list;
	u32 nlportid;
};

struct cyw_cfg80211_cqm_config {
	u32 rssi_hyst;
	s32 last_rssi_event_value;
	int n_rssi_thresholds;
	s32 rssi_thresholds[0];
};

void cyw_cfg80211_destroy_ifaces(struct cyw_cfg80211_registered_device *rdev);

/* free object */
void cyw_cfg80211_dev_free(struct cyw_cfg80211_registered_device *rdev);

int cyw_cfg80211_dev_rename(struct cyw_cfg80211_registered_device *rdev,
			char *newname);

void ieee80211_set_bitrate_flags(struct wiphy *wiphy);

void cyw_cfg80211_bss_expire(struct cyw_cfg80211_registered_device *rdev);
void cyw_cfg80211_bss_age(struct cyw_cfg80211_registered_device *rdev,
                      unsigned long age_secs);
void cyw_cfg80211_update_assoc_bss_entry(struct wireless_dev *wdev,
				     struct ieee80211_channel *channel);

/* IBSS */
int __cyw_cfg80211_join_ibss(struct cyw_cfg80211_registered_device *rdev,
			 struct net_device *dev,
			 struct cyw_cfg80211_ibss_params *params,
			 struct cyw_cfg80211_cached_keys *connkeys);
void cyw_cfg80211_clear_ibss(struct net_device *dev, bool nowext);
int __cyw_cfg80211_leave_ibss(struct cyw_cfg80211_registered_device *rdev,
			  struct net_device *dev, bool nowext);
int cyw_cfg80211_leave_ibss(struct cyw_cfg80211_registered_device *rdev,
			struct net_device *dev, bool nowext);
void __cyw_cfg80211_ibss_joined(struct net_device *dev, const u8 *bssid,
			    struct ieee80211_channel *channel);
int cyw_cfg80211_ibss_wext_join(struct cyw_cfg80211_registered_device *rdev,
			    struct wireless_dev *wdev);

/* mesh */
extern const struct mesh_config default_mesh_config;
extern const struct mesh_setup default_mesh_setup;
int __cyw_cfg80211_join_mesh(struct cyw_cfg80211_registered_device *rdev,
			 struct net_device *dev,
			 struct mesh_setup *setup,
			 const struct mesh_config *conf);
int __cyw_cfg80211_leave_mesh(struct cyw_cfg80211_registered_device *rdev,
			  struct net_device *dev);
int cyw_cfg80211_leave_mesh(struct cyw_cfg80211_registered_device *rdev,
			struct net_device *dev);
int cyw_cfg80211_set_mesh_channel(struct cyw_cfg80211_registered_device *rdev,
			      struct wireless_dev *wdev,
			      struct cyw_cfg80211_chan_def *chandef);

/* OCB */
int __cyw_cfg80211_join_ocb(struct cyw_cfg80211_registered_device *rdev,
			struct net_device *dev,
			struct ocb_setup *setup);
int cyw_cfg80211_join_ocb(struct cyw_cfg80211_registered_device *rdev,
		      struct net_device *dev,
		      struct ocb_setup *setup);
int __cyw_cfg80211_leave_ocb(struct cyw_cfg80211_registered_device *rdev,
			 struct net_device *dev);
int cyw_cfg80211_leave_ocb(struct cyw_cfg80211_registered_device *rdev,
		       struct net_device *dev);

/* AP */
int __cyw_cfg80211_stop_ap(struct cyw_cfg80211_registered_device *rdev,
		       struct net_device *dev, bool notify);
int cyw_cfg80211_stop_ap(struct cyw_cfg80211_registered_device *rdev,
		     struct net_device *dev, bool notify);

/* MLME */
int cyw_cfg80211_mlme_auth(struct cyw_cfg80211_registered_device *rdev,
		       struct net_device *dev,
		       struct ieee80211_channel *chan,
		       enum nl80211_auth_type auth_type,
		       const u8 *bssid,
		       const u8 *ssid, int ssid_len,
		       const u8 *ie, int ie_len,
		       const u8 *key, int key_len, int key_idx,
		       const u8 *auth_data, int auth_data_len);
int cyw_cfg80211_mlme_assoc(struct cyw_cfg80211_registered_device *rdev,
			struct net_device *dev,
			struct ieee80211_channel *chan,
			const u8 *bssid,
			const u8 *ssid, int ssid_len,
			struct cyw_cfg80211_assoc_request *req);
int cyw_cfg80211_mlme_deauth(struct cyw_cfg80211_registered_device *rdev,
			 struct net_device *dev, const u8 *bssid,
			 const u8 *ie, int ie_len, u16 reason,
			 bool local_state_change);
int cyw_cfg80211_mlme_disassoc(struct cyw_cfg80211_registered_device *rdev,
			   struct net_device *dev, const u8 *bssid,
			   const u8 *ie, int ie_len, u16 reason,
			   bool local_state_change);
void cyw_cfg80211_mlme_down(struct cyw_cfg80211_registered_device *rdev,
			struct net_device *dev);
int cyw_cfg80211_mlme_register_mgmt(struct wireless_dev *wdev, u32 snd_pid,
				u16 frame_type, const u8 *match_data,
				int match_len);
void cyw_cfg80211_mlme_unreg_wk(struct work_struct *wk);
void cyw_cfg80211_mlme_unregister_socket(struct wireless_dev *wdev, u32 nlpid);
void cyw_cfg80211_mlme_purge_registrations(struct wireless_dev *wdev);
int cyw_cfg80211_mlme_mgmt_tx(struct cyw_cfg80211_registered_device *rdev,
			  struct wireless_dev *wdev,
			  struct cyw_cfg80211_mgmt_tx_params *params,
			  u64 *cookie);
void cyw_cfg80211_oper_and_ht_capa(struct ieee80211_ht_cap *ht_capa,
			       const struct ieee80211_ht_cap *ht_capa_mask);
void cyw_cfg80211_oper_and_vht_capa(struct ieee80211_vht_cap *vht_capa,
				const struct ieee80211_vht_cap *vht_capa_mask);

/* SME events */
int cyw_cfg80211_connect(struct cyw_cfg80211_registered_device *rdev,
		     struct net_device *dev,
		     struct cyw_cfg80211_connect_params *connect,
		     struct cyw_cfg80211_cached_keys *connkeys,
		     const u8 *prev_bssid);
void __cyw_cfg80211_connect_result(struct net_device *dev,
			       struct cyw_cfg80211_connect_resp_params *params,
			       bool wextev);
void __cyw_cfg80211_disconnected(struct net_device *dev, const u8 *ie,
			     size_t ie_len, u16 reason, bool from_ap);
int cyw_cfg80211_disconnect(struct cyw_cfg80211_registered_device *rdev,
			struct net_device *dev, u16 reason,
			bool wextev);
void __cyw_cfg80211_roamed(struct wireless_dev *wdev,
		       struct cyw_cfg80211_roam_info *info);
void __cyw_cfg80211_port_authorized(struct wireless_dev *wdev, const u8 *bssid);
int cyw_cfg80211_mgd_wext_connect(struct cyw_cfg80211_registered_device *rdev,
			      struct wireless_dev *wdev);
void cyw_cfg80211_autodisconnect_wk(struct work_struct *work);

/* SME implementation */
void cyw_cfg80211_conn_work(struct work_struct *work);
void cyw_cfg80211_sme_scan_done(struct net_device *dev);
bool cyw_cfg80211_sme_rx_assoc_resp(struct wireless_dev *wdev, u16 status);
void cyw_cfg80211_sme_rx_auth(struct wireless_dev *wdev, const u8 *buf, size_t len);
void cyw_cfg80211_sme_disassoc(struct wireless_dev *wdev);
void cyw_cfg80211_sme_deauth(struct wireless_dev *wdev);
void cyw_cfg80211_sme_auth_timeout(struct wireless_dev *wdev);
void cyw_cfg80211_sme_assoc_timeout(struct wireless_dev *wdev);
void cyw_cfg80211_sme_abandon_assoc(struct wireless_dev *wdev);

/* internal helpers */
bool cyw_cfg80211_supported_cipher_suite(struct wiphy *wiphy, u32 cipher);
int cyw_cfg80211_validate_key_settings(struct cyw_cfg80211_registered_device *rdev,
				   struct key_params *params, int key_idx,
				   bool pairwise, const u8 *mac_addr);
void __cyw_cfg80211_scan_done(struct work_struct *wk);
void ___cyw_cfg80211_scan_done(struct cyw_cfg80211_registered_device *rdev,
			   bool send_message);
void cyw_cfg80211_add_sched_scan_req(struct cyw_cfg80211_registered_device *rdev,
				 struct cyw_cfg80211_sched_scan_request *req);
int cyw_cfg80211_sched_scan_req_possible(struct cyw_cfg80211_registered_device *rdev,
				     bool want_multi);
void cyw_cfg80211_sched_scan_results_wk(struct work_struct *work);
int cyw_cfg80211_stop_sched_scan_req(struct cyw_cfg80211_registered_device *rdev,
				 struct cyw_cfg80211_sched_scan_request *req,
				 bool driver_initiated);
int __cyw_cfg80211_stop_sched_scan(struct cyw_cfg80211_registered_device *rdev,
			       u64 reqid, bool driver_initiated);
void cyw_cfg80211_upload_connect_keys(struct wireless_dev *wdev);
int cyw_cfg80211_change_iface(struct cyw_cfg80211_registered_device *rdev,
			  struct net_device *dev, enum nl80211_iftype ntype,
			  struct vif_params *params);
void cyw_cfg80211_process_rdev_events(struct cyw_cfg80211_registered_device *rdev);
void cyw_cfg80211_process_wdev_events(struct wireless_dev *wdev);

bool cyw_cfg80211_does_bw_fit_range(const struct ieee80211_freq_range *freq_range,
				u32 center_freq_khz, u32 bw_khz);

extern struct work_struct cyw_cfg80211_disconnect_work;

/**
 * cyw_cfg80211_chandef_dfs_usable - checks if chandef is DFS usable
 * @wiphy: the wiphy to validate against
 * @chandef: the channel definition to check
 *
 * Checks if chandef is usable and we can/need start CAC on such channel.
 *
 * Return: Return true if all channels available and at least
 *	   one channel require CAC (NL80211_DFS_USABLE)
 */
bool cyw_cfg80211_chandef_dfs_usable(struct wiphy *wiphy,
				 const struct cyw_cfg80211_chan_def *chandef);

void cyw_cfg80211_set_dfs_state(struct wiphy *wiphy,
			    const struct cyw_cfg80211_chan_def *chandef,
			    enum nl80211_dfs_state dfs_state);

void cyw_cfg80211_dfs_channels_update_work(struct work_struct *work);

unsigned int
cyw_cfg80211_chandef_dfs_cac_time(struct wiphy *wiphy,
			      const struct cyw_cfg80211_chan_def *chandef);

void cyw_cfg80211_sched_dfs_chan_update(struct cyw_cfg80211_registered_device *rdev);

bool cyw_cfg80211_any_wiphy_oper_chan(struct wiphy *wiphy,
				  struct ieee80211_channel *chan);

bool cyw_cfg80211_beaconing_iface_active(struct wireless_dev *wdev);

bool cyw_cfg80211_is_sub_chan(struct cyw_cfg80211_chan_def *chandef,
			  struct ieee80211_channel *chan);

static inline unsigned int elapsed_jiffies_msecs(unsigned long start)
{
	unsigned long end = jiffies;

	if (end >= start)
		return jiffies_to_msecs(end - start);

	return jiffies_to_msecs(end + (ULONG_MAX - start) + 1);
}

void
cyw_cfg80211_get_chan_state(struct wireless_dev *wdev,
		        struct ieee80211_channel **chan,
		        enum cyw_cfg80211_chan_mode *chanmode,
		        u8 *radar_detect);

int cyw_cfg80211_set_monitor_channel(struct cyw_cfg80211_registered_device *rdev,
				 struct cyw_cfg80211_chan_def *chandef);

int ieee80211_get_ratemask(struct ieee80211_supported_band *sband,
			   const u8 *rates, unsigned int n_rates,
			   u32 *mask);

int cyw_cfg80211_validate_beacon_int(struct cyw_cfg80211_registered_device *rdev,
				 enum nl80211_iftype iftype, u32 beacon_int);

void cyw_cfg80211_update_iface_num(struct cyw_cfg80211_registered_device *rdev,
			       enum nl80211_iftype iftype, int num);

void __cyw_cfg80211_leave(struct cyw_cfg80211_registered_device *rdev,
		      struct wireless_dev *wdev);
void cyw_cfg80211_leave(struct cyw_cfg80211_registered_device *rdev,
		    struct wireless_dev *wdev);

void cyw_cfg80211_stop_p2p_device(struct cyw_cfg80211_registered_device *rdev,
			      struct wireless_dev *wdev);

void cyw_cfg80211_stop_nan(struct cyw_cfg80211_registered_device *rdev,
		       struct wireless_dev *wdev);

struct cyw_cfg80211_internal_bss *
cyw_cfg80211_bss_update(struct cyw_cfg80211_registered_device *rdev,
		    struct cyw_cfg80211_internal_bss *tmp,
		    bool signal_valid, unsigned long ts);
#ifdef CPTCFG_CFG80211_DEVELOPER_WARNINGS
#define CFG80211_DEV_WARN_ON(cond)	WARN_ON(cond)
#else
/*
 * Trick to enable using it as a condition,
 * and also not give a warning when it's
 * not used that way.
 */
#define CFG80211_DEV_WARN_ON(cond)	({bool __r = (cond); __r; })
#endif

void cyw_cfg80211_cqm_config_free(struct wireless_dev *wdev);

void cyw_cfg80211_release_pmsr(struct wireless_dev *wdev, u32 portid);
void cyw_cfg80211_pmsr_wdev_down(struct wireless_dev *wdev);
void cyw_cfg80211_pmsr_free_wk(struct work_struct *work);

#endif /* __NET_WIRELESS_CORE_H */
