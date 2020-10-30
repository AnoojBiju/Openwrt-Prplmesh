/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * SPDX-FileCopyrightText: 2020 the prplMesh contributors (see AUTHORS.md)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#include <ambiorix_impl.h>
#include <bcl/beerocks_event_loop_mock.h>

#include <amxb/amxb.h>
#include <amxb/amxb_be.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object_parameter.h>

#include "amxb_mock.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrEq;
using ::testing::StrictMock;

namespace {

constexpr auto g_param_path            = "Test.Container";
constexpr auto g_param_name_string     = "String";
constexpr auto g_param_value_foo       = "Foo";
constexpr auto g_param_value_bar       = "Bar";
constexpr auto g_odl_filename_template = "ambiorix_test.odl.XXXXXX";
constexpr auto g_odl_contents          = "%define {\n"
                                "    object Test {\n"
                                "        object Container {\n"
                                "            %read-only string String = \"\";\n"
                                "            %read-only datetime Datetime;\n"
                                "            %read-only int32 Int32 = -1;\n"
                                "            %read-only uint32 Uint32 = 1;\n"
                                "            %read-only int64 Int64 = -1;\n"
                                "            %read-only uint64 Uint64 = 1;\n"
                                "            %read-only bool Bool = false;\n"
                                "            %read-only double Double = \"99.9\";\n"
                                "        }\n"
                                "        mib Optional {\n"
                                "            %read-only string String = \"\";\n"
                                "        }\n"
                                "        object Strings [] {\n"
                                "            %read-only string String = \"\";\n"
                                "            counted with NumberOfStrings;\n"
                                "        }\n"
                                "    }\n"
                                "}\n";

class OdlFile {
    char m_odl_filename[FILENAME_MAX];

public:
    OdlFile(const std::string &odl_filename_template, const std::string &odl_contents)
    {
        snprintf(m_odl_filename, sizeof(m_odl_filename), "%s%s", testing::TempDir().c_str(),
                 odl_filename_template.c_str());
        int fd = mkstemp(m_odl_filename);
        EXPECT_GE(fd, 0);
        EXPECT_EQ(write(fd, odl_contents.c_str(), odl_contents.length()), odl_contents.length());
        EXPECT_EQ(close(fd), 0);
    }

    virtual ~OdlFile() { EXPECT_EQ(unlink(m_odl_filename), 0); }

    const char *get_odl_filename() { return m_odl_filename; }
};

class AmbiorixTest : public ::testing::Test {
public:
    AmbiorixTest()
        : m_odl_file(std::string(g_odl_filename_template), std::string(g_odl_contents)){};

protected:
    std::shared_ptr<beerocks::nbapi::AmbiorixImpl> m_ambiorix;

    amxd_object_t *find_object(const std::string &relative_path)
    {
        return amxd_dm_findf(m_datamodel, "%s", relative_path.c_str());
    }

private:
    std::shared_ptr<StrictMock<beerocks::EventLoopMock>> m_event_loop;
    OdlFile m_odl_file;
    StrictMock<AmbxMock> m_amxb_mock;
    amxd_dm_t *m_datamodel = nullptr;

    void SetUp() override
    {
        m_event_loop = std::make_shared<StrictMock<beerocks::EventLoopMock>>();
        m_ambiorix   = std::make_shared<beerocks::nbapi::AmbiorixImpl>(
            m_event_loop, std::vector<beerocks::nbapi::sActionsCallback>(),
            std::vector<beerocks::nbapi::sEvents>());

        EXPECT_CALL(m_amxb_mock, amxb_be_load(_)).WillRepeatedly(Return(0));
        EXPECT_CALL(m_amxb_mock, amxb_connect(_, _)).WillRepeatedly(Return(0));
        // fetch datamodel pointer from amxb_register call
        EXPECT_CALL(m_amxb_mock, amxb_register(_, _))
            .WillRepeatedly(DoAll(SaveArg<1>(&m_datamodel), Return(0)));
        EXPECT_CALL(m_amxb_mock, amxb_get_fd(_)).WillRepeatedly(Return(42));

        EXPECT_CALL(*m_event_loop, register_handlers(_, _)).WillRepeatedly(Return(true));
        EXPECT_TRUE(m_ambiorix->init("/fake/backend.so", "mockbe:/path",
                                     std::string(m_odl_file.get_odl_filename())));
        ASSERT_TRUE(m_datamodel != nullptr);
    }

    void TearDown() override
    {
        EXPECT_CALL(m_amxb_mock, amxb_free(_)).WillRepeatedly(Return());
        EXPECT_CALL(m_amxb_mock, amxb_be_remove_all()).WillRepeatedly(Return());

        EXPECT_CALL(*m_event_loop, remove_handlers(_)).Times(2).WillRepeatedly(Return(true));

        // we need new instance of nbapi for every single test
        // thus manually release pointer managed by shared_ptr
        // Calling reset() in turn calls the object's destructor so previous expectations are satisfied.
        m_ambiorix.reset();
    }
};

TEST_F(AmbiorixTest, set_string_should_succeed)
{
    amxd_object_t *obj = find_object(g_param_path);
    ASSERT_TRUE(obj);
    EXPECT_EQ(amxd_object_set_cstring_t(obj, g_param_name_string, g_param_value_bar),
              amxd_status_ok);
    EXPECT_TRUE(m_ambiorix->set(g_param_path, g_param_name_string, std::string(g_param_value_foo)));
    amxd_status_t status;
    char *value = amxd_object_get_cstring_t(obj, g_param_name_string, &status);
    EXPECT_EQ(status, amxd_status_ok);
    EXPECT_STREQ(value, g_param_value_foo);
    free(value);
}

} // namespace
