#ifndef LEDGER_ASSERT_H
#define LEDGER_ASSERT_H

#include <assert.h>

// Mock Ledger assert macros
#define LEDGER_ASSERT(condition, msg) assert(condition)
#define LEDGER_ASSERT_MSG(condition, msg) assert(condition)

#endif