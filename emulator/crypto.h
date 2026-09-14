#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

BOOL CalculateSha1(
    const BYTE* inputData,
    DWORD dataLen,
    BYTE* outHash)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 20; // SHA-1 is strictly 20 bytes
    BOOL result = FALSE;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            MS_DEF_PROV,
            PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT))
    {
        goto cleanup;
    }

    if (!CryptCreateHash(
            hProv,
            CALG_SHA1,
            0,
            0,
            &hHash))
    {
        goto cleanup;
    }

    if (!CryptHashData(
            hHash,
            inputData,
            dataLen,
            0))
    {
        goto cleanup;
    }

    if (!CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            outHash,
            &hashLen,
            0))
    {
        goto cleanup;
    }

    result = TRUE;

cleanup:
    if (hHash)
        CryptDestroyHash(hHash);

    if (hProv)
        CryptReleaseContext(hProv, 0);

    return result;
}