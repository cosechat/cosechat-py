# Build the wolfCOSE checker and run it over tests/vectors/vectors.json.
#   make WOLFSSL_PREFIX=/path/to/wolfssl/install WOLFCOSE_DIR=/path/to/wolfCOSE
# wolfCOSE must be built with the same WOLFCOSE_FLAGS.

WOLFSSL_PREFIX ?= /usr/local
WOLFCOSE_DIR ?= ../../../wolfCOSE
WOLFCOSE_FLAGS ?= -DWOLFCOSE_EXPERIMENTAL -DWOLFCOSE_ENABLE_EDDSA -DWOLFCOSE_ENABLE_MLDSA \
  -DWOLFCOSE_ENABLE_CHACHA20 -DWOLFCOSE_ENABLE_HPKE_0 -DWOLFCOSE_ENABLE_HPKE_0_KE \
  -DWOLFCOSE_ENABLE_SIGN -DWOLFCOSE_ENABLE_MAC -DWOLFCOSE_ENABLE_ENCRYPT \
  -DWOLFCOSE_ENABLE_HMAC384 -DWOLFCOSE_ENABLE_HMAC512
PYTHON ?= ../../.venv/bin/python

CFLAGS += -std=c99 -O2 -Wall -I$(WOLFCOSE_DIR)/include -I$(WOLFSSL_PREFIX)/include $(WOLFCOSE_FLAGS)
LDLIBS += $(WOLFCOSE_DIR)/libwolfcose.a -L$(WOLFSSL_PREFIX)/lib -lwolfssl
ifeq ($(shell uname),Darwin)
LDLIBS += -framework CoreFoundation -framework Security
endif

check: check.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

cases.txt: make_cases.py ../../tests/vectors/vectors.json
	$(PYTHON) make_cases.py > $@

test: check cases.txt
	./check < cases.txt

clean:
	rm -f check cases.txt

.PHONY: test clean

print-flags:
	@echo $(WOLFCOSE_FLAGS)

.PHONY: print-flags
