#include "../db/db.h"
#include "../src/beerocks/master/tasks/task.h"

class vbss_task : public son::task {

public:
    vbss_task(son::db &database_);
    virtual ~vbss_task() {}
    bool handle_ieee1905_1_msg(const sMacAddr &src_mac,
                               ieee1905_1::CmduMessageRx &cmdu_rx) override;

private:
    son::db &database;
};
