// SPDX-License-Identifier: GPL-2.0
/*
 * SME code for cyw-cfg80211
 * both driver SME event handling and the SME implementation
 * (for nl80211's connect() and wext)
 *
 * Copyright 2009	Johannes Berg <johannes@sipsolutions.net>
 * Copyright (C) 2009   Intel Corporation. All rights reserved.
 * Copyright 2017	Intel Deutschland GmbH
 */

#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/wireless.h>
#include <linux/export.h>
#include <net/iw_handler.h>
#include <net/cyw-cfg80211.h>
#include <net/rtnetlink.h>
#include "nl80211.h"
#include "reg.h"
#include "rdev-ops.h"

/*
 * Software SME in cyw-cfg80211, using auth/assoc/deauth calls to the
 * driver. This is is for implementing nl80211's connect/disconnect
 * and wireless extensions (if configured.)
 */

struct cyw-cfg80211_conn {
	struct cyw-cfg80211_connect_params params;
	/* these are sub-states of the _CONNECTING sme_state */
	enum {
		CFG80211_CONN_SCANNING,
		CFG80211_CONN_SCAN_AGAIN,
		CFG80211_CONN_AUTHENTICATE_NEXT,
		CFG80211_CONN_AUTHENTICATING,
		CFG80211_CONN_AUTH_FAILED_TIMEOUT,
		CFG80211_CONN_ASSOCIATE_NEXT,
		CFG80211_CONN_ASSOCIATING,
		CFG80211_CONN_ASSOC_FAILED,
		CFG80211_CONN_ASSOC_FAILED_TIMEOUT,
		CFG80211_CONN_DEAUTH,
		CFG80211_CONN_ABANDON,
		CFG80211_CONN_CONNECTED,
	} state;
	u8 bssid[ETH_ALEN], prev_bssid[ETH_ALEN];
	const u8 *ie;
	size_t ie_len;
	bool auto_auth, prev_bssid_valid;
};

static void cyw-cfg80211_sme_free(struct wireless_dev *wdev)
{
	if (!wdev->conn)
		return;

	kfree(wdev->conn->ie);
	kfree(wdev->conn);
	wdev->conn = NULL;
}

static int cyw-cfg80211_conn_scan(struct wireless_dev *wdev)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_scan_request *request;
	int n_channels, err;

	ASSERT_RTNL();
	ASSERT_WDEV_LOCK(wdev);

	if (rdev->scan_req || rdev->scan_msg)
		return -EBUSY;

	if (wdev->conn->params.channel)
		n_channels = 1;
	else
		n_channels = ieee80211_get_num_supported_channels(wdev->wiphy);

	request = kzalloc(sizeof(*request) + sizeof(request->ssids[0]) +
			  sizeof(request->channels[0]) * n_channels,
			  GFP_KERNEL);
	if (!request)
		return -ENOMEM;

	if (wdev->conn->params.channel) {
		enum nl80211_band band = wdev->conn->params.channel->band;
		struct ieee80211_supported_band *sband =
			wdev->wiphy->bands[band];

		if (!sband) {
			kfree(request);
			return -EINVAL;
		}
		request->channels[0] = wdev->conn->params.channel;
		request->rates[band] = (1 << sband->n_bitrates) - 1;
	} else {
		int i = 0, j;
		enum nl80211_band band;
		struct ieee80211_supported_band *bands;
		struct ieee80211_channel *channel;

		for (band = 0; band < NUM_NL80211_BANDS; band++) {
			bands = wdev->wiphy->bands[band];
			if (!bands)
				continue;
			for (j = 0; j < bands->n_channels; j++) {
				channel = &bands->channels[j];
				if (channel->flags & IEEE80211_CHAN_DISABLED)
					continue;
				request->channels[i++] = channel;
			}
			request->rates[band] = (1 << bands->n_bitrates) - 1;
		}
		n_channels = i;
	}
	request->n_channels = n_channels;
	request->ssids = (void *)&request->channels[n_channels];
	request->n_ssids = 1;

	memcpy(request->ssids[0].ssid, wdev->conn->params.ssid,
		wdev->conn->params.ssid_len);
	request->ssids[0].ssid_len = wdev->conn->params.ssid_len;

	eth_broadcast_addr(request->bssid);

	request->wdev = wdev;
	request->wiphy = &rdev->wiphy;
	request->scan_start = jiffies;

	rdev->scan_req = request;

	err = rdev_scan(rdev, request);
	if (!err) {
		wdev->conn->state = CFG80211_CONN_SCANNING;
		nl80211_send_scan_start(rdev, wdev);
		dev_hold(wdev->netdev);
	} else {
		rdev->scan_req = NULL;
		kfree(request);
	}
	return err;
}

static int cyw-cfg80211_conn_do_work(struct wireless_dev *wdev,
				 enum nl80211_timeout_reason *treason)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_connect_params *params;
	struct cyw-cfg80211_assoc_request req = {};
	int err;

	ASSERT_WDEV_LOCK(wdev);

	if (!wdev->conn)
		return 0;

	params = &wdev->conn->params;

	switch (wdev->conn->state) {
	case CFG80211_CONN_SCANNING:
		/* didn't find it during scan ... */
		return -ENOENT;
	case CFG80211_CONN_SCAN_AGAIN:
		return cyw-cfg80211_conn_scan(wdev);
	case CFG80211_CONN_AUTHENTICATE_NEXT:
		if (WARN_ON(!rdev->ops->auth))
			return -EOPNOTSUPP;
		wdev->conn->state = CFG80211_CONN_AUTHENTICATING;
		return cyw-cfg80211_mlme_auth(rdev, wdev->netdev,
					  params->channel, params->auth_type,
					  params->bssid,
					  params->ssid, params->ssid_len,
					  NULL, 0,
					  params->key, params->key_len,
					  params->key_idx, NULL, 0);
	case CFG80211_CONN_AUTH_FAILED_TIMEOUT:
		*treason = NL80211_TIMEOUT_AUTH;
		return -ENOTCONN;
	case CFG80211_CONN_ASSOCIATE_NEXT:
		if (WARN_ON(!rdev->ops->assoc))
			return -EOPNOTSUPP;
		wdev->conn->state = CFG80211_CONN_ASSOCIATING;
		if (wdev->conn->prev_bssid_valid)
			req.prev_bssid = wdev->conn->prev_bssid;
		req.ie = params->ie;
		req.ie_len = params->ie_len;
		req.use_mfp = params->mfp != NL80211_MFP_NO;
		req.crypto = params->crypto;
		req.flags = params->flags;
		req.ht_capa = params->ht_capa;
		req.ht_capa_mask = params->ht_capa_mask;
		req.vht_capa = params->vht_capa;
		req.vht_capa_mask = params->vht_capa_mask;

		err = cyw-cfg80211_mlme_assoc(rdev, wdev->netdev, params->channel,
					  params->bssid, params->ssid,
					  params->ssid_len, &req);
		if (err)
			cyw-cfg80211_mlme_deauth(rdev, wdev->netdev, params->bssid,
					     NULL, 0,
					     WLAN_REASON_DEAUTH_LEAVING,
					     false);
		return err;
	case CFG80211_CONN_ASSOC_FAILED_TIMEOUT:
		*treason = NL80211_TIMEOUT_ASSOC;
		/* fall through */
	case CFG80211_CONN_ASSOC_FAILED:
		cyw-cfg80211_mlme_deauth(rdev, wdev->netdev, params->bssid,
				     NULL, 0,
				     WLAN_REASON_DEAUTH_LEAVING, false);
		return -ENOTCONN;
	case CFG80211_CONN_DEAUTH:
		cyw-cfg80211_mlme_deauth(rdev, wdev->netdev, params->bssid,
				     NULL, 0,
				     WLAN_REASON_DEAUTH_LEAVING, false);
		/* fall through */
	case CFG80211_CONN_ABANDON:
		/* free directly, disconnected event already sent */
		cyw-cfg80211_sme_free(wdev);
		return 0;
	default:
		return 0;
	}
}

void cyw-cfg80211_conn_work(struct work_struct *work)
{
	struct cyw-cfg80211_registered_device *rdev =
		container_of(work, struct cyw-cfg80211_registered_device, conn_work);
	struct wireless_dev *wdev;
	u8 bssid_buf[ETH_ALEN], *bssid = NULL;
	enum nl80211_timeout_reason treason;

	rtnl_lock();

	list_for_each_entry(wdev, &rdev->wiphy.wdev_list, list) {
		if (!wdev->netdev)
			continue;

		wdev_lock(wdev);
		if (!netif_running(wdev->netdev)) {
			wdev_unlock(wdev);
			continue;
		}
		if (!wdev->conn ||
		    wdev->conn->state == CFG80211_CONN_CONNECTED) {
			wdev_unlock(wdev);
			continue;
		}
		if (wdev->conn->params.bssid) {
			memcpy(bssid_buf, wdev->conn->params.bssid, ETH_ALEN);
			bssid = bssid_buf;
		}
		treason = NL80211_TIMEOUT_UNSPECIFIED;
		if (cyw-cfg80211_conn_do_work(wdev, &treason)) {
			struct cyw-cfg80211_connect_resp_params cr;

			memset(&cr, 0, sizeof(cr));
			cr.status = -1;
			cr.bssid = bssid;
			cr.timeout_reason = treason;
			__cyw-cfg80211_connect_result(wdev->netdev, &cr, false);
		}
		wdev_unlock(wdev);
	}

	rtnl_unlock();
}

/* Returned bss is reference counted and must be cleaned up appropriately. */
static struct cyw-cfg80211_bss *cyw-cfg80211_get_conn_bss(struct wireless_dev *wdev)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_bss *bss;

	ASSERT_WDEV_LOCK(wdev);

	bss = cyw-cfg80211_get_bss(wdev->wiphy, wdev->conn->params.channel,
			       wdev->conn->params.bssid,
			       wdev->conn->params.ssid,
			       wdev->conn->params.ssid_len,
			       wdev->conn_bss_type,
			       IEEE80211_PRIVACY(wdev->conn->params.privacy));
	if (!bss)
		return NULL;

	memcpy(wdev->conn->bssid, bss->bssid, ETH_ALEN);
	wdev->conn->params.bssid = wdev->conn->bssid;
	wdev->conn->params.channel = bss->channel;
	wdev->conn->state = CFG80211_CONN_AUTHENTICATE_NEXT;
	schedule_work(&rdev->conn_work);

	return bss;
}

static void __cyw-cfg80211_sme_scan_done(struct net_device *dev)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_bss *bss;

	ASSERT_WDEV_LOCK(wdev);

	if (!wdev->conn)
		return;

	if (wdev->conn->state != CFG80211_CONN_SCANNING &&
	    wdev->conn->state != CFG80211_CONN_SCAN_AGAIN)
		return;

	bss = cyw-cfg80211_get_conn_bss(wdev);
	if (bss)
		cyw-cfg80211_put_bss(&rdev->wiphy, bss);
	else
		schedule_work(&rdev->conn_work);
}

void cyw-cfg80211_sme_scan_done(struct net_device *dev)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;

	wdev_lock(wdev);
	__cyw-cfg80211_sme_scan_done(dev);
	wdev_unlock(wdev);
}

void cyw-cfg80211_sme_rx_auth(struct wireless_dev *wdev, const u8 *buf, size_t len)
{
	struct wiphy *wiphy = wdev->wiphy;
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wiphy);
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)buf;
	u16 status_code = le16_to_cpu(mgmt->u.auth.status_code);

	ASSERT_WDEV_LOCK(wdev);

	if (!wdev->conn || wdev->conn->state == CFG80211_CONN_CONNECTED)
		return;

	if (status_code == WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG &&
	    wdev->conn->auto_auth &&
	    wdev->conn->params.auth_type != NL80211_AUTHTYPE_NETWORK_EAP) {
		/* select automatically between only open, shared, leap */
		switch (wdev->conn->params.auth_type) {
		case NL80211_AUTHTYPE_OPEN_SYSTEM:
			if (wdev->connect_keys)
				wdev->conn->params.auth_type =
					NL80211_AUTHTYPE_SHARED_KEY;
			else
				wdev->conn->params.auth_type =
					NL80211_AUTHTYPE_NETWORK_EAP;
			break;
		case NL80211_AUTHTYPE_SHARED_KEY:
			wdev->conn->params.auth_type =
				NL80211_AUTHTYPE_NETWORK_EAP;
			break;
		default:
			/* huh? */
			wdev->conn->params.auth_type =
				NL80211_AUTHTYPE_OPEN_SYSTEM;
			break;
		}
		wdev->conn->state = CFG80211_CONN_AUTHENTICATE_NEXT;
		schedule_work(&rdev->conn_work);
	} else if (status_code != WLAN_STATUS_SUCCESS) {
		struct cyw-cfg80211_connect_resp_params cr;

		memset(&cr, 0, sizeof(cr));
		cr.status = status_code;
		cr.bssid = mgmt->bssid;
		cr.timeout_reason = NL80211_TIMEOUT_UNSPECIFIED;
		__cyw-cfg80211_connect_result(wdev->netdev, &cr, false);
	} else if (wdev->conn->state == CFG80211_CONN_AUTHENTICATING) {
		wdev->conn->state = CFG80211_CONN_ASSOCIATE_NEXT;
		schedule_work(&rdev->conn_work);
	}
}

bool cyw-cfg80211_sme_rx_assoc_resp(struct wireless_dev *wdev, u16 status)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);

	if (!wdev->conn)
		return false;

	if (status == WLAN_STATUS_SUCCESS) {
		wdev->conn->state = CFG80211_CONN_CONNECTED;
		return false;
	}

	if (wdev->conn->prev_bssid_valid) {
		/*
		 * Some stupid APs don't accept reassoc, so we
		 * need to fall back to trying regular assoc;
		 * return true so no event is sent to userspace.
		 */
		wdev->conn->prev_bssid_valid = false;
		wdev->conn->state = CFG80211_CONN_ASSOCIATE_NEXT;
		schedule_work(&rdev->conn_work);
		return true;
	}

	wdev->conn->state = CFG80211_CONN_ASSOC_FAILED;
	schedule_work(&rdev->conn_work);
	return false;
}

void cyw-cfg80211_sme_deauth(struct wireless_dev *wdev)
{
	cyw-cfg80211_sme_free(wdev);
}

void cyw-cfg80211_sme_auth_timeout(struct wireless_dev *wdev)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);

	if (!wdev->conn)
		return;

	wdev->conn->state = CFG80211_CONN_AUTH_FAILED_TIMEOUT;
	schedule_work(&rdev->conn_work);
}

void cyw-cfg80211_sme_disassoc(struct wireless_dev *wdev)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);

	if (!wdev->conn)
		return;

	wdev->conn->state = CFG80211_CONN_DEAUTH;
	schedule_work(&rdev->conn_work);
}

void cyw-cfg80211_sme_assoc_timeout(struct wireless_dev *wdev)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);

	if (!wdev->conn)
		return;

	wdev->conn->state = CFG80211_CONN_ASSOC_FAILED_TIMEOUT;
	schedule_work(&rdev->conn_work);
}

void cyw-cfg80211_sme_abandon_assoc(struct wireless_dev *wdev)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);

	if (!wdev->conn)
		return;

	wdev->conn->state = CFG80211_CONN_ABANDON;
	schedule_work(&rdev->conn_work);
}

static int cyw-cfg80211_sme_get_conn_ies(struct wireless_dev *wdev,
				     const u8 *ies, size_t ies_len,
				     const u8 **out_ies, size_t *out_ies_len)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	u8 *buf;
	size_t offs;

	if (!rdev->wiphy.extended_capabilities_len ||
	    (ies && cyw-cfg80211_find_ie(WLAN_EID_EXT_CAPABILITY, ies, ies_len))) {
		*out_ies = kmemdup(ies, ies_len, GFP_KERNEL);
		if (!*out_ies)
			return -ENOMEM;
		*out_ies_len = ies_len;
		return 0;
	}

	buf = kmalloc(ies_len + rdev->wiphy.extended_capabilities_len + 2,
		      GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (ies_len) {
		static const u8 before_extcapa[] = {
			/* not listing IEs expected to be created by driver */
			WLAN_EID_RSN,
			WLAN_EID_QOS_CAPA,
			WLAN_EID_RRM_ENABLED_CAPABILITIES,
			WLAN_EID_MOBILITY_DOMAIN,
			WLAN_EID_SUPPORTED_REGULATORY_CLASSES,
			WLAN_EID_BSS_COEX_2040,
		};

		offs = ieee80211_ie_split(ies, ies_len, before_extcapa,
					  ARRAY_SIZE(before_extcapa), 0);
		memcpy(buf, ies, offs);
		/* leave a whole for extended capabilities IE */
		memcpy(buf + offs + rdev->wiphy.extended_capabilities_len + 2,
		       ies + offs, ies_len - offs);
	} else {
		offs = 0;
	}

	/* place extended capabilities IE (with only driver capabilities) */
	buf[offs] = WLAN_EID_EXT_CAPABILITY;
	buf[offs + 1] = rdev->wiphy.extended_capabilities_len;
	memcpy(buf + offs + 2,
	       rdev->wiphy.extended_capabilities,
	       rdev->wiphy.extended_capabilities_len);

	*out_ies = buf;
	*out_ies_len = ies_len + rdev->wiphy.extended_capabilities_len + 2;

	return 0;
}

static int cyw-cfg80211_sme_connect(struct wireless_dev *wdev,
				struct cyw-cfg80211_connect_params *connect,
				const u8 *prev_bssid)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_bss *bss;
	int err;

	if (!rdev->ops->auth || !rdev->ops->assoc)
		return -EOPNOTSUPP;

	if (wdev->current_bss) {
		cyw-cfg80211_unhold_bss(wdev->current_bss);
		cyw-cfg80211_put_bss(wdev->wiphy, &wdev->current_bss->pub);
		wdev->current_bss = NULL;

		cyw-cfg80211_sme_free(wdev);
	}

	if (WARN_ON(wdev->conn))
		return -EINPROGRESS;

	wdev->conn = kzalloc(sizeof(*wdev->conn), GFP_KERNEL);
	if (!wdev->conn)
		return -ENOMEM;

	/*
	 * Copy all parameters, and treat explicitly IEs, BSSID, SSID.
	 */
	memcpy(&wdev->conn->params, connect, sizeof(*connect));
	if (connect->bssid) {
		wdev->conn->params.bssid = wdev->conn->bssid;
		memcpy(wdev->conn->bssid, connect->bssid, ETH_ALEN);
	}

	if (cyw-cfg80211_sme_get_conn_ies(wdev, connect->ie, connect->ie_len,
				      &wdev->conn->ie,
				      &wdev->conn->params.ie_len)) {
		kfree(wdev->conn);
		wdev->conn = NULL;
		return -ENOMEM;
	}
	wdev->conn->params.ie = wdev->conn->ie;

	if (connect->auth_type == NL80211_AUTHTYPE_AUTOMATIC) {
		wdev->conn->auto_auth = true;
		/* start with open system ... should mostly work */
		wdev->conn->params.auth_type =
			NL80211_AUTHTYPE_OPEN_SYSTEM;
	} else {
		wdev->conn->auto_auth = false;
	}

	wdev->conn->params.ssid = wdev->ssid;
	wdev->conn->params.ssid_len = wdev->ssid_len;

	/* see if we have the bss already */
	bss = cyw-cfg80211_get_conn_bss(wdev);

	if (prev_bssid) {
		memcpy(wdev->conn->prev_bssid, prev_bssid, ETH_ALEN);
		wdev->conn->prev_bssid_valid = true;
	}

	/* we're good if we have a matching bss struct */
	if (bss) {
		enum nl80211_timeout_reason treason;

		err = cyw-cfg80211_conn_do_work(wdev, &treason);
		cyw-cfg80211_put_bss(wdev->wiphy, bss);
	} else {
		/* otherwise we'll need to scan for the AP first */
		err = cyw-cfg80211_conn_scan(wdev);

		/*
		 * If we can't scan right now, then we need to scan again
		 * after the current scan finished, since the parameters
		 * changed (unless we find a good AP anyway).
		 */
		if (err == -EBUSY) {
			err = 0;
			wdev->conn->state = CFG80211_CONN_SCAN_AGAIN;
		}
	}

	if (err)
		cyw-cfg80211_sme_free(wdev);

	return err;
}

static int cyw-cfg80211_sme_disconnect(struct wireless_dev *wdev, u16 reason)
{
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	int err;

	if (!wdev->conn)
		return 0;

	if (!rdev->ops->deauth)
		return -EOPNOTSUPP;

	if (wdev->conn->state == CFG80211_CONN_SCANNING ||
	    wdev->conn->state == CFG80211_CONN_SCAN_AGAIN) {
		err = 0;
		goto out;
	}

	/* wdev->conn->params.bssid must be set if > SCANNING */
	err = cyw-cfg80211_mlme_deauth(rdev, wdev->netdev,
				   wdev->conn->params.bssid,
				   NULL, 0, reason, false);
 out:
	cyw-cfg80211_sme_free(wdev);
	return err;
}

/*
 * code shared for in-device and software SME
 */

static bool cyw-cfg80211_is_all_idle(void)
{
	struct cyw-cfg80211_registered_device *rdev;
	struct wireless_dev *wdev;
	bool is_all_idle = true;

	/*
	 * All devices must be idle as otherwise if you are actively
	 * scanning some new beacon hints could be learned and would
	 * count as new regulatory hints.
	 * Also if there is any other active beaconing interface we
	 * need not issue a disconnect hint and reset any info such
	 * as chan dfs state, etc.
	 */
	list_for_each_entry(rdev, &cyw-cfg80211_rdev_list, list) {
		list_for_each_entry(wdev, &rdev->wiphy.wdev_list, list) {
			wdev_lock(wdev);
			if (wdev->conn || wdev->current_bss ||
			    cyw-cfg80211_beaconing_iface_active(wdev))
				is_all_idle = false;
			wdev_unlock(wdev);
		}
	}

	return is_all_idle;
}

static void disconnect_work(struct work_struct *work)
{
	rtnl_lock();
	if (cyw-cfg80211_is_all_idle())
		regulatory_hint_disconnect();
	rtnl_unlock();
}

DECLARE_WORK(cyw-cfg80211_disconnect_work, disconnect_work);


/*
 * API calls for drivers implementing connect/disconnect and
 * SME event handling
 */

/* This method must consume bss one way or another */
void __cyw-cfg80211_connect_result(struct net_device *dev,
			       struct cyw-cfg80211_connect_resp_params *cr,
			       bool wextev)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	const u8 *country_ie;
#ifdef CPTCFG_CFG80211_WEXT
	union iwreq_data wrqu;
#endif

	ASSERT_WDEV_LOCK(wdev);

	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_STATION &&
		    wdev->iftype != NL80211_IFTYPE_P2P_CLIENT)) {
		cyw-cfg80211_put_bss(wdev->wiphy, cr->bss);
		return;
	}

	nl80211_send_connect_result(wiphy_to_rdev(wdev->wiphy), dev, cr,
				    GFP_KERNEL);

#ifdef CPTCFG_CFG80211_WEXT
	if (wextev) {
		if (cr->req_ie && cr->status == WLAN_STATUS_SUCCESS) {
			memset(&wrqu, 0, sizeof(wrqu));
			wrqu.data.length = cr->req_ie_len;
			wireless_send_event(dev, IWEVASSOCREQIE, &wrqu,
					    cr->req_ie);
		}

		if (cr->resp_ie && cr->status == WLAN_STATUS_SUCCESS) {
			memset(&wrqu, 0, sizeof(wrqu));
			wrqu.data.length = cr->resp_ie_len;
			wireless_send_event(dev, IWEVASSOCRESPIE, &wrqu,
					    cr->resp_ie);
		}

		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.ap_addr.sa_family = ARPHRD_ETHER;
		if (cr->bssid && cr->status == WLAN_STATUS_SUCCESS) {
			memcpy(wrqu.ap_addr.sa_data, cr->bssid, ETH_ALEN);
			memcpy(wdev->wext.prev_bssid, cr->bssid, ETH_ALEN);
			wdev->wext.prev_bssid_valid = true;
		}
		wireless_send_event(dev, SIOCGIWAP, &wrqu, NULL);
	}
#endif

	if (!cr->bss && (cr->status == WLAN_STATUS_SUCCESS)) {
		WARN_ON_ONCE(!wiphy_to_rdev(wdev->wiphy)->ops->connect);
		cr->bss = cyw-cfg80211_get_bss(wdev->wiphy, NULL, cr->bssid,
					   wdev->ssid, wdev->ssid_len,
					   wdev->conn_bss_type,
					   IEEE80211_PRIVACY_ANY);
		if (cr->bss)
			cyw-cfg80211_hold_bss(bss_from_pub(cr->bss));
	}

	if (wdev->current_bss) {
		cyw-cfg80211_unhold_bss(wdev->current_bss);
		cyw-cfg80211_put_bss(wdev->wiphy, &wdev->current_bss->pub);
		wdev->current_bss = NULL;
	}

	if (cr->status != WLAN_STATUS_SUCCESS) {
		kzfree(wdev->connect_keys);
		wdev->connect_keys = NULL;
		wdev->ssid_len = 0;
		wdev->conn_owner_nlportid = 0;
		if (cr->bss) {
			cyw-cfg80211_unhold_bss(bss_from_pub(cr->bss));
			cyw-cfg80211_put_bss(wdev->wiphy, cr->bss);
		}
		cyw-cfg80211_sme_free(wdev);
		return;
	}

	if (WARN_ON(!cr->bss))
		return;

	wdev->current_bss = bss_from_pub(cr->bss);

	if (!(wdev->wiphy->flags & WIPHY_FLAG_HAS_STATIC_WEP))
		cyw-cfg80211_upload_connect_keys(wdev);

	rcu_read_lock();
	country_ie = ieee80211_bss_get_ie(cr->bss, WLAN_EID_COUNTRY);
	if (!country_ie) {
		rcu_read_unlock();
		return;
	}

	country_ie = kmemdup(country_ie, 2 + country_ie[1], GFP_ATOMIC);
	rcu_read_unlock();

	if (!country_ie)
		return;

	/*
	 * ieee80211_bss_get_ie() ensures we can access:
	 * - country_ie + 2, the start of the country ie data, and
	 * - and country_ie[1] which is the IE length
	 */
	regulatory_hint_country_ie(wdev->wiphy, cr->bss->channel->band,
				   country_ie + 2, country_ie[1]);
	kfree(country_ie);
}

/* Consumes bss object one way or another */
void cyw-cfg80211_connect_done(struct net_device *dev,
			   struct cyw-cfg80211_connect_resp_params *params,
			   gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_event *ev;
	unsigned long flags;
	u8 *next;

	if (params->bss) {
		struct cyw-cfg80211_internal_bss *ibss = bss_from_pub(params->bss);

		if (list_empty(&ibss->list)) {
			struct cyw-cfg80211_bss *found = NULL, *tmp = params->bss;

			found = cyw-cfg80211_get_bss(wdev->wiphy, NULL,
						 params->bss->bssid,
						 wdev->ssid, wdev->ssid_len,
						 wdev->conn_bss_type,
						 IEEE80211_PRIVACY_ANY);
			if (found) {
				/* The same BSS is already updated so use it
				 * instead, as it has latest info.
				 */
				params->bss = found;
			} else {
				/* Update with BSS provided by driver, it will
				 * be freshly added and ref cnted, we can free
				 * the old one.
				 *
				 * signal_valid can be false, as we are not
				 * expecting the BSS to be found.
				 *
				 * keep the old timestamp to avoid confusion
				 */
				cyw-cfg80211_bss_update(rdev, ibss, false,
						    ibss->ts);
			}

			cyw-cfg80211_put_bss(wdev->wiphy, tmp);
		}
	}

	ev = kzalloc(sizeof(*ev) + (params->bssid ? ETH_ALEN : 0) +
		     params->req_ie_len + params->resp_ie_len +
		     params->fils.kek_len + params->fils.pmk_len +
		     (params->fils.pmkid ? WLAN_PMKID_LEN : 0), gfp);
	if (!ev) {
		cyw-cfg80211_put_bss(wdev->wiphy, params->bss);
		return;
	}

	ev->type = EVENT_CONNECT_RESULT;
	next = ((u8 *)ev) + sizeof(*ev);
	if (params->bssid) {
		ev->cr.bssid = next;
		memcpy((void *)ev->cr.bssid, params->bssid, ETH_ALEN);
		next += ETH_ALEN;
	}
	if (params->req_ie_len) {
		ev->cr.req_ie = next;
		ev->cr.req_ie_len = params->req_ie_len;
		memcpy((void *)ev->cr.req_ie, params->req_ie,
		       params->req_ie_len);
		next += params->req_ie_len;
	}
	if (params->resp_ie_len) {
		ev->cr.resp_ie = next;
		ev->cr.resp_ie_len = params->resp_ie_len;
		memcpy((void *)ev->cr.resp_ie, params->resp_ie,
		       params->resp_ie_len);
		next += params->resp_ie_len;
	}
	if (params->fils.kek_len) {
		ev->cr.fils.kek = next;
		ev->cr.fils.kek_len = params->fils.kek_len;
		memcpy((void *)ev->cr.fils.kek, params->fils.kek,
		       params->fils.kek_len);
		next += params->fils.kek_len;
	}
	if (params->fils.pmk_len) {
		ev->cr.fils.pmk = next;
		ev->cr.fils.pmk_len = params->fils.pmk_len;
		memcpy((void *)ev->cr.fils.pmk, params->fils.pmk,
		       params->fils.pmk_len);
		next += params->fils.pmk_len;
	}
	if (params->fils.pmkid) {
		ev->cr.fils.pmkid = next;
		memcpy((void *)ev->cr.fils.pmkid, params->fils.pmkid,
		       WLAN_PMKID_LEN);
		next += WLAN_PMKID_LEN;
	}
	ev->cr.fils.update_erp_next_seq_num = params->fils.update_erp_next_seq_num;
	if (params->fils.update_erp_next_seq_num)
		ev->cr.fils.erp_next_seq_num = params->fils.erp_next_seq_num;
	if (params->bss)
		cyw-cfg80211_hold_bss(bss_from_pub(params->bss));
	ev->cr.bss = params->bss;
	ev->cr.status = params->status;
	ev->cr.timeout_reason = params->timeout_reason;
	ev->cr.authorized = params->authorized;

	spin_lock_irqsave(&wdev->event_lock, flags);
	list_add_tail(&ev->list, &wdev->event_list);
	spin_unlock_irqrestore(&wdev->event_lock, flags);
	queue_work(cyw-cfg80211_wq, &rdev->event_work);
}
EXPORT_SYMBOL(cyw-cfg80211_connect_done);

/* Consumes bss object one way or another */
void __cyw-cfg80211_roamed(struct wireless_dev *wdev,
		       struct cyw-cfg80211_roam_info *info)
{
#ifdef CPTCFG_CFG80211_WEXT
	union iwreq_data wrqu;
#endif
	ASSERT_WDEV_LOCK(wdev);

	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_STATION &&
		    wdev->iftype != NL80211_IFTYPE_P2P_CLIENT))
		goto out;

	if (WARN_ON(!wdev->current_bss))
		goto out;

	cyw-cfg80211_unhold_bss(wdev->current_bss);
	cyw-cfg80211_put_bss(wdev->wiphy, &wdev->current_bss->pub);
	wdev->current_bss = NULL;

	if (WARN_ON(!info->bss))
		return;

	cyw-cfg80211_hold_bss(bss_from_pub(info->bss));
	wdev->current_bss = bss_from_pub(info->bss);

	nl80211_send_roamed(wiphy_to_rdev(wdev->wiphy),
			    wdev->netdev, info, GFP_KERNEL);

#ifdef CPTCFG_CFG80211_WEXT
	if (info->req_ie) {
		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.data.length = info->req_ie_len;
		wireless_send_event(wdev->netdev, IWEVASSOCREQIE,
				    &wrqu, info->req_ie);
	}

	if (info->resp_ie) {
		memset(&wrqu, 0, sizeof(wrqu));
		wrqu.data.length = info->resp_ie_len;
		wireless_send_event(wdev->netdev, IWEVASSOCRESPIE,
				    &wrqu, info->resp_ie);
	}

	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	memcpy(wrqu.ap_addr.sa_data, info->bss->bssid, ETH_ALEN);
	memcpy(wdev->wext.prev_bssid, info->bss->bssid, ETH_ALEN);
	wdev->wext.prev_bssid_valid = true;
	wireless_send_event(wdev->netdev, SIOCGIWAP, &wrqu, NULL);
#endif

	return;
out:
	cyw-cfg80211_put_bss(wdev->wiphy, info->bss);
}

/* Consumes info->bss object one way or another */
void cyw-cfg80211_roamed(struct net_device *dev, struct cyw-cfg80211_roam_info *info,
		     gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_event *ev;
	unsigned long flags;
	u8 *next;

	if (!info->bss) {
		info->bss = cyw-cfg80211_get_bss(wdev->wiphy, info->channel,
					     info->bssid, wdev->ssid,
					     wdev->ssid_len,
					     wdev->conn_bss_type,
					     IEEE80211_PRIVACY_ANY);
	}

	if (WARN_ON(!info->bss))
		return;

	ev = kzalloc(sizeof(*ev) + info->req_ie_len + info->resp_ie_len +
		     info->fils.kek_len + info->fils.pmk_len +
		     (info->fils.pmkid ? WLAN_PMKID_LEN : 0), gfp);
	if (!ev) {
		cyw-cfg80211_put_bss(wdev->wiphy, info->bss);
		return;
	}

	ev->type = EVENT_ROAMED;
	next = ((u8 *)ev) + sizeof(*ev);
	if (info->req_ie_len) {
		ev->rm.req_ie = next;
		ev->rm.req_ie_len = info->req_ie_len;
		memcpy((void *)ev->rm.req_ie, info->req_ie, info->req_ie_len);
		next += info->req_ie_len;
	}
	if (info->resp_ie_len) {
		ev->rm.resp_ie = next;
		ev->rm.resp_ie_len = info->resp_ie_len;
		memcpy((void *)ev->rm.resp_ie, info->resp_ie,
		       info->resp_ie_len);
		next += info->resp_ie_len;
	}
	if (info->fils.kek_len) {
		ev->rm.fils.kek = next;
		ev->rm.fils.kek_len = info->fils.kek_len;
		memcpy((void *)ev->rm.fils.kek, info->fils.kek,
		       info->fils.kek_len);
		next += info->fils.kek_len;
	}
	if (info->fils.pmk_len) {
		ev->rm.fils.pmk = next;
		ev->rm.fils.pmk_len = info->fils.pmk_len;
		memcpy((void *)ev->rm.fils.pmk, info->fils.pmk,
		       info->fils.pmk_len);
		next += info->fils.pmk_len;
	}
	if (info->fils.pmkid) {
		ev->rm.fils.pmkid = next;
		memcpy((void *)ev->rm.fils.pmkid, info->fils.pmkid,
		       WLAN_PMKID_LEN);
		next += WLAN_PMKID_LEN;
	}
	ev->rm.fils.update_erp_next_seq_num = info->fils.update_erp_next_seq_num;
	if (info->fils.update_erp_next_seq_num)
		ev->rm.fils.erp_next_seq_num = info->fils.erp_next_seq_num;
	ev->rm.bss = info->bss;
	ev->rm.authorized = info->authorized;

	spin_lock_irqsave(&wdev->event_lock, flags);
	list_add_tail(&ev->list, &wdev->event_list);
	spin_unlock_irqrestore(&wdev->event_lock, flags);
	queue_work(cyw-cfg80211_wq, &rdev->event_work);
}
EXPORT_SYMBOL(cyw-cfg80211_roamed);

void __cyw-cfg80211_port_authorized(struct wireless_dev *wdev, const u8 *bssid)
{
	ASSERT_WDEV_LOCK(wdev);

	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_STATION))
		return;

	if (WARN_ON(!wdev->current_bss) ||
	    WARN_ON(!ether_addr_equal(wdev->current_bss->pub.bssid, bssid)))
		return;

	nl80211_send_port_authorized(wiphy_to_rdev(wdev->wiphy), wdev->netdev,
				     bssid);
}

void cyw-cfg80211_port_authorized(struct net_device *dev, const u8 *bssid,
			      gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_event *ev;
	unsigned long flags;

	if (WARN_ON(!bssid))
		return;

	ev = kzalloc(sizeof(*ev), gfp);
	if (!ev)
		return;

	ev->type = EVENT_PORT_AUTHORIZED;
	memcpy(ev->pa.bssid, bssid, ETH_ALEN);

	/*
	 * Use the wdev event list so that if there are pending
	 * connected/roamed events, they will be reported first.
	 */
	spin_lock_irqsave(&wdev->event_lock, flags);
	list_add_tail(&ev->list, &wdev->event_list);
	spin_unlock_irqrestore(&wdev->event_lock, flags);
	queue_work(cyw-cfg80211_wq, &rdev->event_work);
}
EXPORT_SYMBOL(cyw-cfg80211_port_authorized);

void __cyw-cfg80211_disconnected(struct net_device *dev, const u8 *ie,
			     size_t ie_len, u16 reason, bool from_ap)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	int i;
#ifdef CPTCFG_CFG80211_WEXT
	union iwreq_data wrqu;
#endif

	ASSERT_WDEV_LOCK(wdev);

	if (WARN_ON(wdev->iftype != NL80211_IFTYPE_STATION &&
		    wdev->iftype != NL80211_IFTYPE_P2P_CLIENT))
		return;

	if (wdev->current_bss) {
		cyw-cfg80211_unhold_bss(wdev->current_bss);
		cyw-cfg80211_put_bss(wdev->wiphy, &wdev->current_bss->pub);
	}

	wdev->current_bss = NULL;
	wdev->ssid_len = 0;
	wdev->conn_owner_nlportid = 0;
	kzfree(wdev->connect_keys);
	wdev->connect_keys = NULL;

	nl80211_send_disconnected(rdev, dev, reason, ie, ie_len, from_ap);

	/* stop critical protocol if supported */
	if (rdev->ops->crit_proto_stop && rdev->crit_proto_nlportid) {
		rdev->crit_proto_nlportid = 0;
		rdev_crit_proto_stop(rdev, wdev);
	}

	/*
	 * Delete all the keys ... pairwise keys can't really
	 * exist any more anyway, but default keys might.
	 */
	if (rdev->ops->del_key)
		for (i = 0; i < 6; i++)
			rdev_del_key(rdev, dev, i, false, NULL);

	rdev_set_qos_map(rdev, dev, NULL);

#ifdef CPTCFG_CFG80211_WEXT
	memset(&wrqu, 0, sizeof(wrqu));
	wrqu.ap_addr.sa_family = ARPHRD_ETHER;
	wireless_send_event(dev, SIOCGIWAP, &wrqu, NULL);
	wdev->wext.connect.ssid_len = 0;
#endif

	schedule_work(&cyw-cfg80211_disconnect_work);
}

void cyw-cfg80211_disconnected(struct net_device *dev, u16 reason,
			   const u8 *ie, size_t ie_len,
			   bool locally_generated, gfp_t gfp)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);
	struct cyw-cfg80211_event *ev;
	unsigned long flags;

	ev = kzalloc(sizeof(*ev) + ie_len, gfp);
	if (!ev)
		return;

	ev->type = EVENT_DISCONNECTED;
	ev->dc.ie = ((u8 *)ev) + sizeof(*ev);
	ev->dc.ie_len = ie_len;
	memcpy((void *)ev->dc.ie, ie, ie_len);
	ev->dc.reason = reason;
	ev->dc.locally_generated = locally_generated;

	spin_lock_irqsave(&wdev->event_lock, flags);
	list_add_tail(&ev->list, &wdev->event_list);
	spin_unlock_irqrestore(&wdev->event_lock, flags);
	queue_work(cyw-cfg80211_wq, &rdev->event_work);
}
EXPORT_SYMBOL(cyw-cfg80211_disconnected);

/*
 * API calls for nl80211/wext compatibility code
 */
int cyw-cfg80211_connect(struct cyw-cfg80211_registered_device *rdev,
		     struct net_device *dev,
		     struct cyw-cfg80211_connect_params *connect,
		     struct cyw-cfg80211_cached_keys *connkeys,
		     const u8 *prev_bssid)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	int err;

	ASSERT_WDEV_LOCK(wdev);

	/*
	 * If we have an ssid_len, we're trying to connect or are
	 * already connected, so reject a new SSID unless it's the
	 * same (which is the case for re-association.)
	 */
	if (wdev->ssid_len &&
	    (wdev->ssid_len != connect->ssid_len ||
	     memcmp(wdev->ssid, connect->ssid, wdev->ssid_len)))
		return -EALREADY;

	/*
	 * If connected, reject (re-)association unless prev_bssid
	 * matches the current BSSID.
	 */
	if (wdev->current_bss) {
		if (!prev_bssid)
			return -EALREADY;
		if (!ether_addr_equal(prev_bssid, wdev->current_bss->pub.bssid))
			return -ENOTCONN;
	}

	/*
	 * Reject if we're in the process of connecting with WEP,
	 * this case isn't very interesting and trying to handle
	 * it would make the code much more complex.
	 */
	if (wdev->connect_keys)
		return -EINPROGRESS;

	cyw-cfg80211_oper_and_ht_capa(&connect->ht_capa_mask,
				  rdev->wiphy.ht_capa_mod_mask);
	cyw-cfg80211_oper_and_vht_capa(&connect->vht_capa_mask,
				   rdev->wiphy.vht_capa_mod_mask);

	if (connkeys && connkeys->def >= 0) {
		int idx;
		u32 cipher;

		idx = connkeys->def;
		cipher = connkeys->params[idx].cipher;
		/* If given a WEP key we may need it for shared key auth */
		if (cipher == WLAN_CIPHER_SUITE_WEP40 ||
		    cipher == WLAN_CIPHER_SUITE_WEP104) {
			connect->key_idx = idx;
			connect->key = connkeys->params[idx].key;
			connect->key_len = connkeys->params[idx].key_len;

			/*
			 * If ciphers are not set (e.g. when going through
			 * iwconfig), we have to set them appropriately here.
			 */
			if (connect->crypto.cipher_group == 0)
				connect->crypto.cipher_group = cipher;

			if (connect->crypto.n_ciphers_pairwise == 0) {
				connect->crypto.n_ciphers_pairwise = 1;
				connect->crypto.ciphers_pairwise[0] = cipher;
			}
		}

		connect->crypto.wep_keys = connkeys->params;
		connect->crypto.wep_tx_key = connkeys->def;
	} else {
		if (WARN_ON(connkeys))
			return -EINVAL;
	}

	wdev->connect_keys = connkeys;
	memcpy(wdev->ssid, connect->ssid, connect->ssid_len);
	wdev->ssid_len = connect->ssid_len;

	wdev->conn_bss_type = connect->pbss ? IEEE80211_BSS_TYPE_PBSS :
					      IEEE80211_BSS_TYPE_ESS;

	if (!rdev->ops->connect)
		err = cyw-cfg80211_sme_connect(wdev, connect, prev_bssid);
	else
		err = rdev_connect(rdev, dev, connect);

	if (err) {
		wdev->connect_keys = NULL;
		/*
		 * This could be reassoc getting refused, don't clear
		 * ssid_len in that case.
		 */
		if (!wdev->current_bss)
			wdev->ssid_len = 0;
		return err;
	}

	return 0;
}

int cyw-cfg80211_disconnect(struct cyw-cfg80211_registered_device *rdev,
			struct net_device *dev, u16 reason, bool wextev)
{
	struct wireless_dev *wdev = dev->ieee80211_ptr;
	int err = 0;

	ASSERT_WDEV_LOCK(wdev);

	kzfree(wdev->connect_keys);
	wdev->connect_keys = NULL;

	wdev->conn_owner_nlportid = 0;

	if (wdev->conn)
		err = cyw-cfg80211_sme_disconnect(wdev, reason);
	else if (!rdev->ops->disconnect)
		cyw-cfg80211_mlme_down(rdev, dev);
	else if (wdev->ssid_len)
		err = rdev_disconnect(rdev, dev, reason);

	/*
	 * Clear ssid_len unless we actually were fully connected,
	 * in which case cyw-cfg80211_disconnected() will take care of
	 * this later.
	 */
	if (!wdev->current_bss)
		wdev->ssid_len = 0;

	return err;
}

/*
 * Used to clean up after the connection / connection attempt owner socket
 * disconnects
 */
void cyw-cfg80211_autodisconnect_wk(struct work_struct *work)
{
	struct wireless_dev *wdev =
		container_of(work, struct wireless_dev, disconnect_wk);
	struct cyw-cfg80211_registered_device *rdev = wiphy_to_rdev(wdev->wiphy);

	wdev_lock(wdev);

	if (wdev->conn_owner_nlportid) {
		switch (wdev->iftype) {
		case NL80211_IFTYPE_ADHOC:
			__cyw-cfg80211_leave_ibss(rdev, wdev->netdev, false);
			break;
		case NL80211_IFTYPE_AP:
		case NL80211_IFTYPE_P2P_GO:
			__cyw-cfg80211_stop_ap(rdev, wdev->netdev, false);
			break;
		case NL80211_IFTYPE_MESH_POINT:
			__cyw-cfg80211_leave_mesh(rdev, wdev->netdev);
			break;
		case NL80211_IFTYPE_STATION:
		case NL80211_IFTYPE_P2P_CLIENT:
			/*
			 * Use disconnect_bssid if still connecting and
			 * ops->disconnect not implemented.  Otherwise we can
			 * use cyw-cfg80211_disconnect.
			 */
			if (rdev->ops->disconnect || wdev->current_bss)
				cyw-cfg80211_disconnect(rdev, wdev->netdev,
						    WLAN_REASON_DEAUTH_LEAVING,
						    true);
			else
				cyw-cfg80211_mlme_deauth(rdev, wdev->netdev,
						     wdev->disconnect_bssid,
						     NULL, 0,
						     WLAN_REASON_DEAUTH_LEAVING,
						     false);
			break;
		default:
			break;
		}
	}

	wdev_unlock(wdev);
}
