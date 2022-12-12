/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2016-2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <bcl/beerocks_backport.h>

#include "include/ambiorix_variant.h"

#define GET_VARIANT_AS(TYPE_ID, TYPE_NAME, OUT_VAL, IN_VAR_PTR)                                    \
    {                                                                                              \
        bool ret = false;                                                                          \
        amxc_var_t conv_var;                                                                       \
        amxc_var_init(&conv_var);                                                                  \
        if (!!(ret = (amxc_var_convert(&conv_var, IN_VAR_PTR, TYPE_ID) == 0))) {                   \
            OUT_VAL = amxc_var_get_const_##TYPE_NAME(&conv_var);                                   \
        }                                                                                          \
        amxc_var_clean(&conv_var);                                                                 \
        return ret;                                                                                \
    }

#define SET_VARIANT_AS(TYPE_NAME, OUT_VAR_PTR, IN_VALUE)                                           \
    {                                                                                              \
        return (amxc_var_set_##TYPE_NAME(OUT_VAR_PTR, IN_VALUE) == 0);                             \
    }

namespace beerocks {
namespace wbapi {

amxc_var_t *AmbiorixVariantBaseAccess::amxc_var_ptr(AmbiorixVariant &obj) { return obj.m_var_ctx; }

AmbiorixVariant::AmbiorixVariant(const uint32_t type)
{
    if (amxc_var_new(&m_var_ctx) == 0) {
        bound = true;
        if (type != AMXC_VAR_ID_NULL) {
            LOG_IF(!set_type(type), ERROR) << "Fail to set variant type!";
        }
    } else {
        LOG(ERROR) << "Fail to allocate variant!";
    }
}

AmbiorixVariant::AmbiorixVariant(amxc_var_t *data, bool is_bound) : m_var_ctx(data), bound(is_bound)
{
}

AmbiorixVariant::~AmbiorixVariant()
{
    if (bound) {
        amxc_var_delete(&m_var_ctx);
    }
}

AmbiorixVariant::AmbiorixVariant(const AmbiorixVariant &other)
{
    if (!other.bound) {
        bound     = false;
        m_var_ctx = other.m_var_ctx;
    } else if (amxc_var_new(&m_var_ctx) == 0) {
        bound = true;
        amxc_var_copy(m_var_ctx, other.m_var_ctx);
    }
}

AmbiorixVariant::AmbiorixVariant(AmbiorixVariant &&other)
{
    m_var_ctx   = other.m_var_ctx;
    bound       = other.bound;
    other.bound = false;
}

AmbiorixVariant &AmbiorixVariant::operator=(const AmbiorixVariant &other)
{
    if (this != &other) {
        bound = true;
        amxc_var_copy(m_var_ctx, other.m_var_ctx);
    }
    return *this;
}

bool AmbiorixVariant::empty() const { return amxc_var_is_null(m_var_ctx); }

void AmbiorixVariant::reset() { amxc_var_clean(m_var_ctx); }

bool AmbiorixVariant::set_type(const uint32_t type)
{
    return (amxc_var_set_type(m_var_ctx, type) == 0);
}

uint32_t AmbiorixVariant::get_type() const { return amxc_var_type_of(m_var_ctx); }

AmbiorixVariantSmartPtr AmbiorixVariant::create(const uint32_t type)
{
    return std::make_unique<AmbiorixVariant>(type);
}

AmbiorixVariantSmartPtr AmbiorixVariant::bind(amxc_var_t *data)
{
    return std::make_unique<AmbiorixVariant>(data, true);
}

AmbiorixVariantSmartPtr AmbiorixVariant::wrap(amxc_var_t *data)
{
    return std::make_unique<AmbiorixVariant>(data, false);
}

AmbiorixVariantSmartPtr AmbiorixVariant::find_child(const std::string &key) const
{
    return wrap(GET_ARG(m_var_ctx, key.c_str()));
}

AmbiorixVariantSmartPtr AmbiorixVariant::find_child(uint32_t index) const
{
    return wrap(GETI_ARG(m_var_ctx, index));
}

AmbiorixVariantSmartPtr AmbiorixVariant::find_child_deep(const std::string &path) const
{
    return wrap(GETP_ARG(m_var_ctx, path.c_str()));
}

AmbiorixVariantSmartPtr AmbiorixVariant::first_child() const
{
    return wrap(amxc_var_get_first(m_var_ctx));
}

AmbiorixVariantSmartPtr AmbiorixVariant::last_child() const
{
    return wrap(amxc_var_get_last(m_var_ctx));
}

void AmbiorixVariant::detach()
{
    if (m_var_ctx) {
        amxc_var_take_it(m_var_ctx);
        bound = true;
    }
}

bool AmbiorixVariant::set(const amxc_var_t *value)
{
    return (amxc_var_copy(m_var_ctx, value) == 0);
}
bool AmbiorixVariant::set(const char *value) { SET_VARIANT_AS(cstring_t, m_var_ctx, value) }
bool AmbiorixVariant::set(const std::string &value)
{
    std::string local(value);
    SET_VARIANT_AS(cstring_t, m_var_ctx, local.c_str())
}
bool AmbiorixVariant::set(bool value) { SET_VARIANT_AS(bool, m_var_ctx, value) }
bool AmbiorixVariant::set(char value) { SET_VARIANT_AS(int8_t, m_var_ctx, value) }
bool AmbiorixVariant::set(int8_t value) { SET_VARIANT_AS(int8_t, m_var_ctx, value) }
bool AmbiorixVariant::set(int16_t value) { SET_VARIANT_AS(int16_t, m_var_ctx, value) }
bool AmbiorixVariant::set(int value) { SET_VARIANT_AS(int32_t, m_var_ctx, value) }
bool AmbiorixVariant::set(int64_t value) { SET_VARIANT_AS(int64_t, m_var_ctx, value) }
bool AmbiorixVariant::set(uint8_t value) { SET_VARIANT_AS(uint8_t, m_var_ctx, value) }
bool AmbiorixVariant::set(uint16_t value) { SET_VARIANT_AS(uint16_t, m_var_ctx, value) }
bool AmbiorixVariant::set(uint32_t value) { SET_VARIANT_AS(uint32_t, m_var_ctx, value) }
bool AmbiorixVariant::set(uint64_t value) { SET_VARIANT_AS(uint64_t, m_var_ctx, value) }
bool AmbiorixVariant::set(double value) { SET_VARIANT_AS(double, m_var_ctx, value) }

static int amxc_var_set_float(amxc_var_t *var, float value)
{
    int ret;
    if ((ret = amxc_var_set_type(var, AMXC_VAR_ID_FLOAT)) == 0) {
        var->data.f = value;
    }
    return ret;
}
bool AmbiorixVariant::set(float value) { SET_VARIANT_AS(float, m_var_ctx, value) }

bool AmbiorixVariant::get(std::string &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_CSTRING, cstring_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(bool &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_BOOL, bool, value, m_var_ctx)
}
bool AmbiorixVariant::get(char &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_INT8, int8_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(int8_t &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_INT8, int8_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(int16_t &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_INT16, int16_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(int &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_INT32, int32_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(int64_t &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_INT64, int64_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(uint8_t &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_UINT8, uint8_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(uint16_t &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_UINT16, uint16_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(uint32_t &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_UINT32, uint32_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(uint64_t &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_UINT64, uint64_t, value, m_var_ctx)
}
bool AmbiorixVariant::get(double &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_DOUBLE, double, value, m_var_ctx)
}
static float amxc_var_get_const_float(const amxc_var_t *const var)
{
    if (var) {
        return var->data.f;
    }
    return 0;
}
bool AmbiorixVariant::get(float &value) const
{
    GET_VARIANT_AS(AMXC_VAR_ID_FLOAT, float, value, m_var_ctx)
}

bool AmbiorixVariant::get_childs(AmbiorixVariantListSmartPtr &result, bool extract)
{
    if (!result) {
        result = std::move(std::make_unique<AmbiorixVariantList>());
    } else {
        result->clear();
    }
    amxc_var_for_each(elt, m_var_ctx)
    {
        if (extract) {
            amxc_var_take_it(elt);
        }
        result->push_back(AmbiorixVariant(elt, extract));
    }
    return true;
}

bool AmbiorixVariant::get_childs(AmbiorixVariantMapSmartPtr &result, bool extract)
{
    if (!result) {
        result = std::move(std::make_unique<AmbiorixVariantMap>());
    } else {
        result->clear();
    }
    amxc_var_for_each(elt, m_var_ctx)
    {
        auto key = amxc_var_key(elt);
        if (!key) {
            return false;
        }
        if (extract) {
            amxc_var_take_it(elt);
        }
        result->emplace(key, AmbiorixVariant(elt, extract));
    }
    return true;
}

} // namespace wbapi
} // namespace beerocks
