///////////////////////////////////////
// AUTO GENERATED FILE - DO NOT EDIT //
///////////////////////////////////////
/*
#############################################################################
# INTEL CONFIDENTIAL
# Copyright 2018 Intel Corporation All Rights Reserved.
#
# The source code contained or described herein and all documents related to
# the source code ("Material") are owned by Intel Corporation or its
# suppliers or licensors.  Title to the Material remains with Intel
# Corporation or its suppliers and licensors.  The Material contains trade
# secrets and proprietary and confidential information of Intel or its
# suppliers and licensors.  The Material is protected by worldwide copyright
# and trade secret laws and treaty provisions. No part of the Material may
# be used, copied, reproduced, modified, published, uploaded, posted,
# transmitted, distributed, or disclosed in any way without Intel's prior
# express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or
# delivery of the Materials,  either expressly, by implication, inducement,
# estoppel or otherwise.  Any license under such intellectual property
# rights must be express and approved by Intel in writing.
#############################################################################
*/

#ifndef _CmduMessageTX_H_
#define _CmduMessageTX_H_

#include "CmduMessage.h"

#include "ieee_1905_1/tlvVendorSpecific.h"

namespace ieee1905_1 {

class CmduMessageTx : public CmduMessage {

public:

    CmduMessageTx(uint8_t* buff, size_t buff_len);
    ~CmduMessageTx();

public:
    std::shared_ptr<cCmduHeader> create(uint16_t id, eMessageType message_type);
    std::shared_ptr<cCmduHeader> create(uint16_t id, tlvVendorSpecific::eVendorOUI voui);

    bool finalize(bool swap_needed);
};

}; // close namespace: ieee1905_1

#endif //_CmduMessageTX_H_
