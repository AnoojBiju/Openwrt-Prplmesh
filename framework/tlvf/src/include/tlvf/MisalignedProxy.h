/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2024 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef TLVF_MISALIGNED_PROXY
#define TLVF_MISALIGNED_PROXY

#include <cstdint>

#ifndef MISALIGNED_DWORD_ACCESS_NEEDS_SPECIAL_HANDLING

using tlvf_int64_t  = int64_t &;
using tlvf_uint64_t = uint64_t &;

using tlvf_int64_t_const  = const int64_t &;
using tlvf_uint64_t_const = const uint64_t &;

#else

template <typename Int> class tlvfMisalignedProxy {
protected:
    void *buf;

public:
    explicit tlvfMisalignedProxy(Int &i) : buf(&i) {}

    operator Int() const
    {
        Int ret;
        memcpy(&ret, buf, sizeof(Int));
        return ret;
    }
};

template <typename Int> class tlvfMisalignedRWProxy : public tlvfMisalignedProxy<Int> {
    using tlvfMisalignedProxy<Int>::tlvfMisalignedProxy;

public:
    Int operator=(Int i)
    {
        memcpy(this->buf, &i, sizeof(Int));
        return i;
    }
};

using tlvf_int64_t  = tlvfMisalignedRWProxy<int64_t>;
using tlvf_uint64_t = tlvfMisalignedRWProxy<uint64_t>;

using tlvf_int64_t_const  = tlvfMisalignedProxy<int64_t>;
using tlvf_uint64_t_const = tlvfMisalignedProxy<uint64_t>;

#endif

#endif
