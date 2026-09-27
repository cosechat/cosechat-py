/*
 * Verify cosiechat vectors with stock wolfCOSE + wolfCrypt (the Arduino stack).
 * Reads cases from stdin (see make_cases.py), one per line:
 *   name op key[,key...] aad|- data expect
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfcose/wolfcose.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

#define MAX_KEYS 4
#define MAX_BUF 65536
#define MAX_RECIPIENTS 8

typedef struct {
  WOLFCOSE_KEY k;
  ecc_key ecc;
  ed25519_key ed;
  wc_MlDsaKey ml;
  uint8_t raw[8192];
  size_t rawLen;
} Key;

static uint8_t scratch[MAX_BUF];
static uint8_t plain[MAX_BUF];

static size_t unhex (const char* s, uint8_t* out, size_t max) {
  size_t n = strlen(s) / 2;
  if (n > max) {
    return (size_t)-1;
  }
  for (size_t i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(s + 2 * i, "%2x", &v) != 1) {
      return (size_t)-1;
    }
    out[i] = (uint8_t)v;
  }
  return n;
}

static int key_load (Key* key, const char* hex) {
  WOLFCOSE_KEY_INFO info;
  int ret;
  key->rawLen = unhex(hex, key->raw, sizeof(key->raw));
  if (key->rawLen == (size_t)-1) {
    return -1;
  }
  ret = wc_CoseKey_PeekInfo(key->raw, key->rawLen, &info);
  if (ret != 0) {
    return ret;
  }
  wc_CoseKey_Init(&key->k);
  if (info.kty == WOLFCOSE_KTY_OKP && info.crv == WOLFCOSE_CRV_ED25519) {
    wc_ed25519_init(&key->ed);
    wc_CoseKey_SetEd25519(&key->k, &key->ed);
  } else if (info.kty == WOLFCOSE_KTY_EC2) {
    wc_ecc_init(&key->ecc);
    wc_CoseKey_SetEcc(&key->k, info.crv, &key->ecc);
  } else if (info.kty == WOLFCOSE_KTY_AKP) {
    wc_MlDsaKey_Init(&key->ml, NULL, INVALID_DEVID);
    wc_CoseKey_SetMlDsa(&key->k, info.alg, &key->ml);
  }
  return wc_CoseKey_Decode(&key->k, key->raw, key->rawLen);
}

static int run (const char* op, Key* keys, int nkeys, const uint8_t* aad, size_t aadLen,
  const uint8_t* data, size_t dataLen, const uint8_t** out, size_t* outLen) {
  WOLFCOSE_HDR hdr;
  int ret = -1;
  if (strcmp(op, "sign1") == 0) {
    return wc_CoseSign1_Verify(&keys[0].k, data, dataLen, NULL, 0, aad, aadLen, scratch,
      sizeof(scratch), &hdr, out, outLen);
  }
  if (strcmp(op, "sign") == 0) {
    /* the identity rule: every signing key must have a valid signature */
    for (int i = 0; i < nkeys; i++) {
      ret = wc_CoseSign_Verify(&keys[i].k, (size_t)i, data, dataLen, NULL, 0, aad, aadLen,
        scratch, sizeof(scratch), &hdr, out, outLen);
      if (ret != 0) {
        return ret;
      }
    }
    return ret;
  }
  if (strcmp(op, "mac0") == 0) {
    return wc_CoseMac0_Verify(&keys[0].k, data, dataLen, NULL, 0, aad, aadLen, scratch,
      sizeof(scratch), &hdr, out, outLen);
  }
  if (strcmp(op, "enc0") == 0 || strcmp(op, "hpke0") == 0) {
    if (op[0] == 'e') {
      ret = wc_CoseEncrypt0_Decrypt(&keys[0].k, data, dataLen, NULL, 0, aad, aadLen, scratch,
        sizeof(scratch), &hdr, plain, sizeof(plain), outLen);
    } else {
      ret = wc_CoseHpkeEncrypt0_Decrypt(&keys[0].k, data, dataLen, NULL, 0, aad, aadLen,
        scratch, sizeof(scratch), &hdr, plain, sizeof(plain), outLen);
    }
    *out = plain;
    return ret;
  }
  if (strcmp(op, "enc") == 0 || strcmp(op, "mac") == 0) {
    /* recipients carry no kid, so try each entry like the reference does */
    WOLFCOSE_RECIPIENT r = {WOLFCOSE_ALG_HPKE_0_KE, &keys[0].k, NULL, 0};
    /* SPEC 2: a KEM key tagged HPKE-0 may be used as HPKE-0-KE (same KEM) */
    if (keys[0].k.alg == WOLFCOSE_ALG_HPKE_0) {
      keys[0].k.alg = WOLFCOSE_ALG_HPKE_0_KE;
    }
    int first = 0;
    for (size_t i = 0; i < MAX_RECIPIENTS; i++) {
      if (op[0] == 'e') {
        ret = wc_CoseEncrypt_Decrypt(&r, i, data, dataLen, NULL, 0, aad, aadLen, scratch,
          sizeof(scratch), &hdr, plain, sizeof(plain), outLen);
        *out = plain;
      } else {
        ret = wc_CoseMac_Verify(&r, i, data, dataLen, NULL, 0, aad, aadLen, scratch,
          sizeof(scratch), &hdr, out, outLen);
      }
      if (ret == 0) {
        return 0;
      }
      if (ret != WOLFCOSE_E_INVALID_ARG || i == 0) {
        first = (first == 0) ? ret : first;
      }
    }
    return first ? first : ret;
  }
  fprintf(stderr, "unknown op %s\n", op);
  return -1;
}

int main (void) {
  static char line[4 * MAX_BUF];
  static uint8_t data[MAX_BUF];
  static uint8_t expect[MAX_BUF];
  static uint8_t aad[256];
  static Key keys[MAX_KEYS];
  int pass = 0;
  int fail = 0;

  wolfCrypt_Init();
  while (fgets(line, sizeof(line), stdin)) {
    char* name = strtok(line, " \n");
    char* op = strtok(NULL, " \n");
    char* keyList = strtok(NULL, " \n");
    char* aadHex = strtok(NULL, " \n");
    char* dataHex = strtok(NULL, " \n");
    char* expectHex = strtok(NULL, " \n");
    int nkeys = 0;
    int ret = 0;
    size_t aadLen = 0;
    size_t dataLen;
    size_t expectLen;
    const uint8_t* out = NULL;
    size_t outLen = 0;
    char* save = NULL;

    if (!expectHex) {
      continue;
    }
    for (char* k = strtok_r(keyList, ",", &save); k && nkeys < MAX_KEYS;
         k = strtok_r(NULL, ",", &save)) {
      ret = key_load(&keys[nkeys++], k);
      if (ret != 0) {
        break;
      }
    }
    if (strcmp(aadHex, "-") != 0) {
      aadLen = unhex(aadHex, aad, sizeof(aad));
    }
    dataLen = unhex(dataHex, data, sizeof(data));
    expectLen = unhex(expectHex, expect, sizeof(expect));
    if (ret == 0) {
      ret = run(op, keys, nkeys, aad, aadLen, data, dataLen, &out, &outLen);
    } else {
      printf("FAIL %-44s key load %d\n", name, ret);
      fail++;
      continue;
    }
    if (ret == 0 && outLen == expectLen && memcmp(out, expect, expectLen) == 0) {
      printf("ok   %-44s %s\n", name, op);
      pass++;
    } else {
      printf("FAIL %-44s %s ret=%d len=%zu/%zu\n", name, op, ret, outLen, expectLen);
      fail++;
    }
  }
  wolfCrypt_Cleanup();
  printf("\n%d passed, %d failed\n", pass, fail);
  return fail ? 1 : 0;
}
