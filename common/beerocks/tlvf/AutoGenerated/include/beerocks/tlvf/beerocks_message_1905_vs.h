///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////

/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef _BEEROCKS_TLVF_BEEROCKS_MESSAGE_1905_VS_H_
#define _BEEROCKS_TLVF_BEEROCKS_MESSAGE_1905_VS_H_

#include <cstddef>
#include <stdint.h>
#include <tlvf/swap.h>
#include <string.h>
#include <memory>
#include <tlvf/BaseClass.h>
#include <tlvf/ClassList.h>
#include <tuple>
#include "bcl/beerocks_message_structs.h"
#include "beerocks/tlvf/beerocks_message_action.h"

namespace beerocks_message {


class tlvVsClientAssociationEvent : public BaseClass
{
    public:
        tlvVsClientAssociationEvent(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvVsClientAssociationEvent(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvVsClientAssociationEvent();

        static eActionOp_1905_VS get_action_op(){
            return (eActionOp_1905_VS)(ACTION_TLV_VENDOR_SPECIFIC);
        }
        sMacAddr& mac();
        sMacAddr& bssid();
        int8_t& vap_id();
        //relevant only on connect event
        beerocks::message::sRadioCapabilities& capabilities();
        //relevant only on disconnect event
        uint8_t& disconnect_reason();
        //relevant only on disconnect event
        uint8_t& disconnect_source();
        //relevant only on disconnect event
        uint8_t& disconnect_type();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eActionOp_1905_VS* m_action_op = nullptr;
        sMacAddr* m_mac = nullptr;
        sMacAddr* m_bssid = nullptr;
        int8_t* m_vap_id = nullptr;
        beerocks::message::sRadioCapabilities* m_capabilities = nullptr;
        uint8_t* m_disconnect_reason = nullptr;
        uint8_t* m_disconnect_source = nullptr;
        uint8_t* m_disconnect_type = nullptr;
};
typedef struct sScanRequestExtension {
    sMacAddr radio_mac;
    uint32_t dwell_time_ms;
    void struct_swap(){
        radio_mac.struct_swap();
        tlvf_swap(32, reinterpret_cast<uint8_t*>(&dwell_time_ms));
    }
    void struct_init(){
        radio_mac.struct_init();
    }
} __attribute__((packed)) sScanRequestExtension;


class tlvVsChannelScanRequestExtension : public BaseClass
{
    public:
        tlvVsChannelScanRequestExtension(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvVsChannelScanRequestExtension(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvVsChannelScanRequestExtension();

        static eActionOp_1905_VS get_action_op(){
            return (eActionOp_1905_VS)(ACTION_TLV_VENDOR_SPECIFIC);
        }
        uint8_t& scan_requests_list_length();
        std::tuple<bool, sScanRequestExtension&> scan_requests_list(size_t idx);
        bool alloc_scan_requests_list(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eActionOp_1905_VS* m_action_op = nullptr;
        uint8_t* m_scan_requests_list_length = nullptr;
        sScanRequestExtension* m_scan_requests_list = nullptr;
        size_t m_scan_requests_list_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

class tlvVsChannelScanReportDone : public BaseClass
{
    public:
        tlvVsChannelScanReportDone(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvVsChannelScanReportDone(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvVsChannelScanReportDone();

        static eActionOp_1905_VS get_action_op(){
            return (eActionOp_1905_VS)(ACTION_TLV_VENDOR_SPECIFIC);
        }
        uint8_t& report_done();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eActionOp_1905_VS* m_action_op = nullptr;
        uint8_t* m_report_done = nullptr;
};

class tlvVsOnDemandChannelSelection : public BaseClass
{
    public:
        tlvVsOnDemandChannelSelection(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvVsOnDemandChannelSelection(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvVsOnDemandChannelSelection();

        static eActionOp_1905_VS get_action_op(){
            return (eActionOp_1905_VS)(ACTION_TLV_VENDOR_SPECIFIC);
        }
        sMacAddr& radio_mac();
        uint8_t& CSA_count();
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eActionOp_1905_VS* m_action_op = nullptr;
        sMacAddr* m_radio_mac = nullptr;
        uint8_t* m_CSA_count = nullptr;
};
typedef struct sBssidVapId {
    sMacAddr bssid;
    int8_t vap_id;
    void struct_swap(){
        bssid.struct_swap();
    }
    void struct_init(){
        bssid.struct_init();
    }
} __attribute__((packed)) sBssidVapId;


class tlvVsBssidIfaceMapping : public BaseClass
{
    public:
        tlvVsBssidIfaceMapping(uint8_t* buff, size_t buff_len, bool parse = false);
        explicit tlvVsBssidIfaceMapping(std::shared_ptr<BaseClass> base, bool parse = false);
        ~tlvVsBssidIfaceMapping();

        static eActionOp_1905_VS get_action_op(){
            return (eActionOp_1905_VS)(ACTION_TLV_VENDOR_SPECIFIC);
        }
        uint8_t& bssid_vap_id_map_length();
        std::tuple<bool, sBssidVapId&> bssid_vap_id_map(size_t idx);
        bool alloc_bssid_vap_id_map(size_t count = 1);
        void class_swap() override;
        bool finalize() override;
        static size_t get_initial_size();

    private:
        bool init();
        eActionOp_1905_VS* m_action_op = nullptr;
        uint8_t* m_bssid_vap_id_map_length = nullptr;
        sBssidVapId* m_bssid_vap_id_map = nullptr;
        size_t m_bssid_vap_id_map_idx__ = 0;
        int m_lock_order_counter__ = 0;
};

}; // close namespace: beerocks_message

#endif //_BEEROCKS/TLVF_BEEROCKS_MESSAGE_1905_VS_H_
