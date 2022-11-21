#include "gtest/gtest.h"

#include <checksec.h>

TEST(Winchecksec, NoDynamicBase32) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-no-dynamicbase.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isDynamicBase());
    EXPECT_FALSE(checksec.isASLR());
}

TEST(Winchecksec, NoDynamicBase64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-dynamicbase.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isDynamicBase());
    EXPECT_FALSE(checksec.isASLR());
}

TEST(Winchecksec, NoHighEntropyVA32) {
    // NOTE: 32-bit programs obviously don't support 64-bit ASLR.
    auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isHighEntropyVA());
    EXPECT_TRUE(checksec.isASLR());
}

TEST(Winchecksec, HighEntropyVA64) {
    // By default, 64-bit PEs use their full address space for ASLR.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isHighEntropyVA());
        EXPECT_TRUE(checksec.isASLR());
    }

    // ...but it can be disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-highentropyva.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isHighEntropyVA());
        EXPECT_TRUE(checksec.isASLR());
    }
}

TEST(Winchecksec, NX32) {
    // By default, modern PEs support NX/DEP.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isNX());
    }

    // ...but it can be disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-no-nxcompat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isNX());
    }
}

TEST(Winchecksec, NX64) {
    // By default, modern PEs support NX/DEP.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isNX());
    }

    // ...but it can be disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-nxcompat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isNX());
    }
}

TEST(Winchecksec, CFG32) {
    // By default, modern PEs do not support CFG.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }

    // ...but it can be enabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-yes-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isCFG());
    }

    // ...or explicitly disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/32/pegoat-no-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }
}

TEST(Winchecksec, CFG64) {
    // By default, modern PEs do not support CFG.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }

    // ...but it can be enabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-yes-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_TRUE(checksec.isCFG());
    }

    // ...or explicitly disabled.
    {
        auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-cfg.exe";

        auto checksec = checksec::Checksec(path);

        EXPECT_FALSE(checksec.isCFG());
    }
}

TEST(Winchecksec, NoCetCompat64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-no-cetcompat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_FALSE(checksec.isCetCompat());
}

TEST(Winchecksec, CetCompat64) {
    auto *path = WINCHECKSEC_TEST_ASSETS "/64/pegoat-cetcompat.exe";

    auto checksec = checksec::Checksec(path);

    EXPECT_TRUE(checksec.isCetCompat());
}
