/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#ifndef AMBIORIX_AMXC_H
#define AMBIORIX_AMXC_H

#include <amxc/amxc.h>

class AMXCListContainer {
public:
    class ConstAMXCListContainerIterator {
    private:
        const amxc_llist_it_t* current;
        const amxc_llist_it_t* next;

    public:
        ConstAMXCListContainerIterator(const amxc_llist_it_t* start)
            : current(start),
              next(amxc_llist_it_get_next(start)) {}

        // Prefix increment
        ConstAMXCListContainerIterator& operator++() {
            current = next;
            next = amxc_llist_it_get_next(current);
            return *this;
        }

        // Dereference
        const amxc_llist_it_t* operator*() const {
            return current;
        }

        // Equality check
        bool operator!=(const ConstAMXCListContainerIterator& other) const {
            return current != other.current;
        }
    };

    class AMXCListContainerIterator {
    private:
        amxc_llist_it_t* current;
        amxc_llist_it_t* next;

    public:
        AMXCListContainerIterator(amxc_llist_it_t* start)
            : current(start),
              next(amxc_llist_it_get_next(start)) {}

        // Prefix increment
        AMXCListContainerIterator& operator++() {
            current = next;
            next = amxc_llist_it_get_next(current);
            return *this;
        }

        // Dereference
        amxc_llist_it_t* operator*() {
            return current;
        }

        // Equality check
        bool operator!=(const AMXCListContainerIterator& other) const {
            return current != other.current;
        }
    };

private:
    amxc_llist_t* head;

public:
    AMXCListContainer(amxc_llist_t* start) : head(start) {}
    AMXCListContainer(const amxc_llist_t* start) : head(const_cast<amxc_llist_t*>(start)) {}
    // begin and end methods for range-based for loop
    AMXCListContainerIterator begin() {
        return AMXCListContainerIterator(amxc_llist_get_first(head));
    }

    AMXCListContainerIterator end() {
        return AMXCListContainerIterator(nullptr);  // nullptr signifies the end of list
    }
};


class AMXContainer {
public:
    class AMXContainerIterator {
    private:
        amxc_var_t* current;
        amxc_var_t* next;

    public:
        AMXContainerIterator(amxc_var_t* start) : current(start), next(amxc_var_get_next(start)) {}

        // Prefix increment
        AMXContainerIterator& operator++() {
            current = next;
            next = amxc_var_get_next(current);
            return *this;
        }

        // Dereference
        amxc_var_t* operator*() {
            return current;
        }

        // Equality check
        bool operator!=(const AMXContainerIterator& other) const {
            return current != other.current;
        }
    };

private:
    amxc_var_t* head;

public:
    AMXContainer(amxc_var_t* start) : head(start) {}

    AMXContainerIterator begin() const {
        return AMXContainerIterator(head);
    }

    AMXContainerIterator end() const {
        return AMXContainerIterator(nullptr);
    }

    amxc_var_t* addNewKeyAmxcLlist(const char* key, const amxc_llist_t* list) {
        return amxc_var_add_new_key_amxc_llist_t(head, key, list);
    }

    amxc_var_t* addNewKeyCString(const char* key, const char* const val) {
        return amxc_var_add_new_key_cstring_t(head, key, val);
    }

    amxc_var_t* addNewKeyUint32(const char* key, uint32_t val) {
        return amxc_var_add_new_key_uint32_t(head, key, val);
    }

    amxc_var_t* addNewKeyBool(const char* key, bool boolean) {
        return amxc_var_add_new_key_bool(head, key, boolean);
    }
};

#endif
