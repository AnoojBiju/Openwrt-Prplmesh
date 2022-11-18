/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2022 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_VARIANT_H_
#define AMBIORIX_VARIANT_H_

// Ambiorix

#include <amxc/amxc.h>

#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb.h>

#include <memory>

#include <vector>

#include <easylogging++.h>

namespace beerocks {
namespace wbapi {

class AmbiorixVariant;
using AmbiorixVariantSmartPtr     = std::unique_ptr<AmbiorixVariant>;
using AmbiorixVariantList         = std::vector<AmbiorixVariant>;
using AmbiorixVariantListSmartPtr = std::unique_ptr<AmbiorixVariantList>;
using AmbiorixVariantMap          = std::map<std::string, AmbiorixVariant>;
using AmbiorixVariantMapSmartPtr  = std::unique_ptr<AmbiorixVariantMap>;

/**
 * @Class AmbiorixVariantBaseAccess: utility class giving access to basic amxc variant pointer
 */
class AmbiorixVariantBaseAccess {
public:
    amxc_var_t *amxc_var_ptr(AmbiorixVariant &obj);

protected:
    AmbiorixVariantBaseAccess()          = default;
    virtual ~AmbiorixVariantBaseAccess() = default;
};

/**
 * @class AmbiorixVariant: wrapper class for amxc_var_t struct
 */
class AmbiorixVariant {
public:
    /**
     * @brief Class constructor: allocates internal variant context
     * and set optionnally the variant type
     * @param[in] type: optional initial variant type
     */
    explicit AmbiorixVariant(const uint32_t type = AMXC_VAR_ID_NULL);

    /**
     * @brief Class constructor: referencing an external variant context.
     * @param[in] data: external variant context: pointed memory
     * @param[in] bound: flag indicating whether the pointed memory will be freed on destruction
     * MUST be available along lifetime of AmbiorixVariant object
     */
    AmbiorixVariant(amxc_var_t *data, bool bound);

    /**
     * @brief Class copy constructor
     */
    AmbiorixVariant(const AmbiorixVariant &other);

    /**
     * @brief Class move constructor
     */
    AmbiorixVariant(AmbiorixVariant &&other);

    /**
     * @brief Class destructor: frees variant context when bound
     */
    virtual ~AmbiorixVariant();

    /**
     * @brief Class assignment operator
     */
    AmbiorixVariant &operator=(const AmbiorixVariant &);

    /**
     * @brief Factory method: creating smart pointer for AmbiorixVariant object
     * with empty local variant context.
     *
     * @param[in] type: optional initial variant type
     * @return unique_ptr for newly created AmbiorixVariant object
     */
    static AmbiorixVariantSmartPtr create(const uint32_t type = AMXC_VAR_ID_NULL);

    /**
     * @brief Factory method: creating smart pointer for AmbiorixVariant object
     * bound to external amx variant struct.
     * The bound context will be freed when object destructor is called
     *
     * @param[in] data: bound external variant data
     * @return unique_ptr for newly created AmbiorixVariant object
     */
    static AmbiorixVariantSmartPtr bind(amxc_var_t *data);

    /**
     * @brief Factory method: creating smart pointer for AmbiorixVariant object
     * referencing an external amx variant struct.
     * This mapping is passive: the referenced context is not freed by object destructor.
     *
     * @param[in] data: referenced external variant data
     * @return unique_ptr for newly created AmbiorixVariant object
     */
    static AmbiorixVariantSmartPtr wrap(amxc_var_t *data);

    /**
     * @brief methods to set Ambiorix variant value
     *
     * @param[in] value: Typed variant value
     * @return bool True when value is set successfully
     */
    bool set(const amxc_var_t *value);
    bool set(const char *value);
    bool set(const std::string &value);
    bool set(bool value);
    bool set(char value);
    bool set(int8_t value);
    bool set(int16_t value);
    bool set(int value);
    bool set(int64_t value);
    bool set(uint8_t value);
    bool set(uint16_t value);
    bool set(uint32_t value);
    bool set(uint64_t value);
    bool set(double value);
    bool set(float value);

    /**
     * @brief methods to get Ambiorix variant value
     *
     * @return return true when read/conversion is successful
     */
    bool get(std::string &value) const;
    bool get(bool &value) const;
    bool get(char &value) const;
    bool get(int8_t &value) const;
    bool get(int16_t &value) const;
    bool get(int &value) const;
    bool get(int64_t &value) const;
    bool get(uint8_t &value) const;
    bool get(uint16_t &value) const;
    bool get(uint32_t &value) const;
    bool get(uint64_t &value) const;
    bool get(double &value) const;
    bool get(float &value) const;

    /**
     * @brief template method to get Ambiorix variant value
     *
     * @return return local (or converted) typed value
     */
    template <typename T> T get() const
    {
        T value = T();
        get(value);
        return value;
    }

    /**
     * @brief Templated conversion function
     *
     * @return typed variant value when supported, otherwise default type empty value
     */
    template <typename T> operator T() const { return get<T>(); }

    /**
     * @brief Template Factory method: copy a provided value into a newly
     * created AmbiorixVariant object.
     *
     * @param[in] value: Typed value
     * @return unique_ptr for newly created AmbiorixVariant object
     */
    template <typename T> static AmbiorixVariantSmartPtr copy(const T &value)
    {
        auto var = create();
        if (var) {
            var->set(value);
        }
        return var;
    }

    /**
     * brief Adds a typed variant child, with key name, to a composite variant.
     *
     * @param[in] key: child key name
     * @param[in] value: Typed variant value
     * @return bool True when child is added successfully
     */
    template <typename T> bool add_child(const std::string &key, const T &value)
    {
        auto sub_var = amxc_var_add_new_key(m_var_ctx, key.c_str());
        if (!sub_var) {
            LOG(ERROR) << "fail to add param " << key << " to variant type "
                       << std::to_string(get_type());
            return false;
        }
        if (AmbiorixVariant(sub_var, false).set(value)) {
            return true;
        }
        amxc_var_delete(&sub_var);
        return false;
    }

    /**
     * @brief Finds a variant child, matching a provided key name
     * into a composite variant.
     *
     * @param[in] key: child key name
     * @return unique_ptr for AmbiorixVariant object wrapping the fetched variant,
     * otherwise empty is returned.
     */
    AmbiorixVariantSmartPtr find_child(const std::string &key) const;

    /**
     * @brief Finds a variant child, matching by index (order)
     * into a composite variant.
     *
     * @param[in] index: child index
     * @return unique_ptr for AmbiorixVariant object wrapping the fetched variant,
     * otherwise empty is returned.
     */
    AmbiorixVariantSmartPtr find_child(uint32_t index) const;

    /**
     * @brief Fetch deeply a variant child, using a relative tree path
     * into a composite variant.
     *
     * @param[in] path: deep child path
     * @return unique_ptr for AmbiorixVariant object wrapping the fetched variant,
     * otherwise empty is returned.
     */
    AmbiorixVariantSmartPtr find_child_deep(const std::string &path) const;

    /**
     * @brief Returns first child of a composite variant.
     *
     * @return unique_ptr for AmbiorixVariant object wrapping the fetched variant,
     * otherwise empty is returned.
     */
    AmbiorixVariantSmartPtr first_child() const;

    /**
     * @brief Returns last child of a composite variant.
     *
     * @return unique_ptr for AmbiorixVariant object wrapping the fetched variant,
     * otherwise empty is returned.
     */
    AmbiorixVariantSmartPtr last_child() const;

    /**
     * @brief Detach a variant from a parent hierarchy and bind it
     */
    void detach();

    /**
     * @brief Template method reads child typed value (with possible conversion)
     *
     * @param[out] value: Typed variant value
     * @param[in] key: child key name or index
     * @return true when child is found and read, false otherwise
     */
    template <typename T, typename K> bool read_child(T &value, const K &key) const
    {
        auto child = find_child(key);
        return (child && child->get(value));
    }

    /**
     * @brief Builds vector of child variants, of a composite variant
     *
     * @param[out] childs: resulting vector of child variants
     * @param[in] extract: flag whether extracting child from container
     * @return true when childs are retrieved successfully
     */
    bool get_childs(AmbiorixVariantListSmartPtr &result, bool extract);

    /**
     * @brief Builds map of child variants, sorted by variant path,
     * of a composite variant.
     * (Only applicable for htable composite variant.)
     *
     * @param[out] childs: resulting map of child variants
     * @param[in] extract: flag whether extracting child from container
     * @return true when childs are retrieved successfully
     */
    bool get_childs(AmbiorixVariantMapSmartPtr &result, bool extract);

    /**
     * @brief Template method provides set of references to variant childs
     * of a composite variant
     *
     * @return resulting set of child variants
     */
    template <typename T> T read_childs()
    {
        T result = T();
        get_childs(result, false);
        return result;
    }

    /**
     * @brief Template method breaks down a composite variant
     * into a set of variant childs
     *
     * @return resulting set of child variants
     */
    template <typename T> T take_childs()
    {
        T result = T();
        get_childs(result, true);
        return result;
    }

    /**
     * @brief Returns whether the variant context is empty
     */
    bool empty() const;

    /**
     * @brief Resets variant context
     */
    void reset();

    /**
     * @brief Set type of Ambiorix variant content.
     * Valid type values are among AMXC_VAR_ID_XXX
     *
     * @return return true when type is set successfully
     */
    bool set_type(const uint32_t type);

    /**
     * @brief Returns type of Ambiorix variant content.
     * Valid type values are among AMXC_VAR_ID_XXX
     */
    uint32_t get_type() const;

    /**
     * @brief Returns pointer to ambiorix variant context
     */
    friend amxc_var_t *AmbiorixVariantBaseAccess::amxc_var_ptr(AmbiorixVariant &obj);

private:
    /**
     * @brief variant context
     */
    amxc_var_t *m_var_ctx = nullptr;

    /**
     * @brief flag indicating whether the referenced context has to be cleared on destruction
     */
    bool bound;
};

} // namespace wbapi
} // namespace beerocks

#endif /* AMBIORIX_VARIANT_H_ */
