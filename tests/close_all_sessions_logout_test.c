/* close_all_sessions_logout_test.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * Regression test: C_CloseAllSessions must log the application out of the
 * token (PKCS#11 v2.40/v3.0 section 5.6.7 / C_Logout semantics). Before the
 * fix, WP11_Slot_CloseSessions closed every session for the slot but never
 * reset the token login state, so a session opened after C_CloseAllSessions
 * still reported CKS_RW_USER_FUNCTIONS instead of CKS_RW_PUBLIC_SESSION.
 * This test logs in as CKU_USER, calls C_CloseAllSessions, reopens a session
 * and asserts the reopened session is logged out (CKS_RW_PUBLIC_SESSION).
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include "testdata.h"

#define CAS_TEST_DIR "./store/close_all_sessions_logout_test"
#define WOLFPKCS11_TOKEN_FILENAME "wp11_token_0000000000000001"

static unsigned char soPin[]   = "password123456";
static unsigned char userPin[] = "wolfpkcs11-user";

static int test_passed = 0;
static int test_failed = 0;

#define CHECK_RV(rv, op, expected) do {                                       \
    if ((rv) != (expected)) {                                                 \
        fprintf(stderr, "FAIL: %s: expected 0x%lx, got 0x%lx\n", op,          \
                (unsigned long)(expected), (unsigned long)(rv));              \
        test_failed++;                                                        \
    } else {                                                                  \
        printf("PASS: %s\n", op);                                             \
        test_passed++;                                                        \
    }                                                                         \
} while (0)

#define CHECK_STATE(got, want, op) do {                                       \
    if ((got) != (want)) {                                                    \
        fprintf(stderr, "FAIL: %s: expected state %lu, got %lu\n", op,        \
                (unsigned long)(want), (unsigned long)(got));                 \
        test_failed++;                                                        \
    } else {                                                                  \
        printf("PASS: %s (state=%lu)\n", op, (unsigned long)(got));           \
        test_passed++;                                                        \
    }                                                                         \
} while (0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;

static CK_RV pkcs11_load(void)
{
    CK_RV ret;
#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;
    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        dlclose(dlib);
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK)
        return ret;
#endif
    return CKR_OK;
}

static void pkcs11_unload(void)
{
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
    funcList = NULL;
}

static void cleanup_store(const char* dir)
{
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s" PATH_SEP "%s", dir,
             WOLFPKCS11_TOKEN_FILENAME);
    (void)remove(filepath);
}

static int run_test(void)
{
    CK_RV rv;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = 0;
    CK_SESSION_INFO info;
    CK_UTF8CHAR label[32];
    int sessFlags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, "cas-logout", 10);

    /* Start from a fresh, uninitialized token. */
    cleanup_store(CAS_TEST_DIR);

    rv = pkcs11_load();
    CHECK_RV(rv, "load library", CKR_OK);
    if (rv != CKR_OK)
        return -1;

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    rv = funcList->C_Initialize(&args);
    CHECK_RV(rv, "C_Initialize", CKR_OK);
    if (rv != CKR_OK)
        goto out;

    rv = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    CHECK_RV(rv, "C_GetSlotList", CKR_OK);
    if (rv != CKR_OK || slotCount == 0)
        goto out;
    slot = slotList[0];

    /* Initialize the token and set a user PIN. */
    rv = funcList->C_InitToken(slot, soPin, (CK_ULONG)XSTRLEN((char*)soPin),
                               label);
    CHECK_RV(rv, "C_InitToken", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession (SO)", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = funcList->C_Login(session, CKU_SO, soPin,
                           (CK_ULONG)XSTRLEN((char*)soPin));
    CHECK_RV(rv, "C_Login(CKU_SO)", CKR_OK);
    rv = funcList->C_InitPIN(session, userPin,
                             (CK_ULONG)XSTRLEN((char*)userPin));
    CHECK_RV(rv, "C_InitPIN", CKR_OK);
    funcList->C_Logout(session);
    funcList->C_CloseSession(session);
    session = 0;

    /* Log in as USER and confirm the session reports USER functions. */
    rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession (user)", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = funcList->C_Login(session, CKU_USER, userPin,
                           (CK_ULONG)XSTRLEN((char*)userPin));
    CHECK_RV(rv, "C_Login(CKU_USER)", CKR_OK);
    rv = funcList->C_GetSessionInfo(session, &info);
    CHECK_RV(rv, "C_GetSessionInfo (after login)", CKR_OK);
    CHECK_STATE(info.state, CKS_RW_USER_FUNCTIONS,
                "logged-in session is RW_USER_FUNCTIONS");

    /* Close all sessions for the slot. Per PKCS#11 this logs the application
     * out of the token. */
    rv = funcList->C_CloseAllSessions(slot);
    CHECK_RV(rv, "C_CloseAllSessions", CKR_OK);
    session = 0;

    /* A newly opened R/W session must now be logged out (RW_PUBLIC_SESSION),
     * not still in RW_USER_FUNCTIONS. This is the regression under test. */
    rv = funcList->C_OpenSession(slot, sessFlags, NULL, NULL, &session);
    CHECK_RV(rv, "C_OpenSession (after CloseAllSessions)", CKR_OK);
    if (rv != CKR_OK)
        goto out;
    rv = funcList->C_GetSessionInfo(session, &info);
    CHECK_RV(rv, "C_GetSessionInfo (after reopen)", CKR_OK);
    CHECK_STATE(info.state, CKS_RW_PUBLIC_SESSION,
                "reopened session is logged out (RW_PUBLIC_SESSION)");

out:
    if (session != 0)
        funcList->C_CloseSession(session);
    funcList->C_Finalize(NULL);
    pkcs11_unload();
    return 0;
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

#ifndef WOLFPKCS11_NO_ENV
    XSETENV("WOLFPKCS11_TOKEN_PATH", CAS_TEST_DIR, 1);
#endif

    printf("=== wolfPKCS11 C_CloseAllSessions logout test ===\n");
    run_test();

    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_failed);
    if (test_failed == 0)
        printf("ALL TESTS PASSED!\n");
    else
        printf("SOME TESTS FAILED!\n");

    return (test_failed == 0) ? 0 : 1;
}
