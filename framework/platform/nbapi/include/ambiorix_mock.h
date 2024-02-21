/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_MOCK_H
#define AMBIORIX_MOCK_H

#include "ambiorix.h"

#include <bcl/beerocks_backport.h>

#include <gmock/gmock.h>

namespace beerocks {
namespace nbapi {

/**
 * @class Ambiorix
 * @brief Mock version of Ambiorix class
 */
class AmbiorixMock : public Ambiorix {
public:
    struct Transaction : SingleObjectTransaction {
        AmbiorixMock *parent;
        std::string relative_path;

#define TRANS_SET(TYPE)                                                                            \
    bool set(const std::string &parameter, const TYPE &value) override                             \
    {                                                                                              \
        return parent->set(relative_path, parameter, value);                                       \
    }
        TRANS_SET(int8_t)
        TRANS_SET(int16_t)
        TRANS_SET(int32_t)
        TRANS_SET(int64_t)
        TRANS_SET(uint8_t)
        TRANS_SET(uint16_t)
        TRANS_SET(uint32_t)
        TRANS_SET(uint64_t)
        TRANS_SET(bool)
        TRANS_SET(double)
        bool set(const std::string &parameter, const char *value) override
        {
            return parent->set(relative_path, parameter, value);
        }
        TRANS_SET(sMacAddr)
#undef TRANS_SET
        bool set_time(const std::string &time_stamp) override
        {
            return parent->set_time(relative_path, time_stamp);
        }
        bool set_current_time(const std::string &param) override
        {
            return parent->set_current_time(relative_path, param);
        }
    };
    std::unique_ptr<SingleObjectTransaction> begin_transaction(const std::string &relative_path,
                                                               bool new_instance) override
    {
        auto ret = std::make_unique<Transaction>();

        ret->parent        = this;
        ret->relative_path = new_instance ? add_instance(relative_path) : relative_path;

        return ret;
    }
    std::string commit_transaction(std::unique_ptr<SingleObjectTransaction> trans) override
    {
        return static_cast<Transaction &>(*trans).relative_path;
    }

    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const int8_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const int16_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const int32_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const int64_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const uint8_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const uint16_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const uint32_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const uint64_t &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const bool &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const double &value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const char *value));
    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const sMacAddr &value));

    MOCK_METHOD(bool, set,
                (const std::string &relative_path, const std::string &parameter,
                 const std::string &value));

    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, int8_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, int16_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, int32_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, int64_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, uint8_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, uint16_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, uint32_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, uint64_t *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, double *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, bool *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object,
                 std::string *param_val),
                (override));
    MOCK_METHOD(bool, read_param,
                (const std::string &path_to_object, const std::string &object, sMacAddr *param_val),
                (override));

    MOCK_METHOD(std::string, add_instance, (const std::string &relative_path));
    MOCK_METHOD(bool, remove_instance, (const std::string &relative_path, uint32_t index),
                (override));
    MOCK_METHOD(uint32_t, get_instance_index,
                (const std::string &specific_path, const std::string &key), (override));
    MOCK_METHOD(std::string, get_datamodel_time_format, (), (override));
    MOCK_METHOD(bool, remove_all_instances, (const std::string &relative_path), (override));
    MOCK_METHOD(bool, add_optional_subobject,
                (const std::string &path_to_obj, const std::string &subobject_name), (override));
    MOCK_METHOD(bool, remove_optional_subobject,
                (const std::string &path_to_obj, const std::string &subobject_name), (override));

    MOCK_METHOD(bool, set_current_time,
                (const std::string &path_to_object, const std::string &object));
    MOCK_METHOD(bool, set_time, (const std::string &path_to_object, const std::string &time_stamp),
                (const std::string &path_to_object, const std::string &object));
};

} // namespace nbapi
} // namespace beerocks

#endif // AMBIORIX_MOCK_H
