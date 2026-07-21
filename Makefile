# Nullkey — one-word checks.  Usage:  make test | cov | lint | sec | fuzz | all
PY  = ./.venv/bin/python
BIN = ./.venv/bin
SRC = nullkey.py chat.py crypto.py identity.py contacts.py net.py ratchet.py wire.py fuzz_parser.py
TESTS = test_ratchet.py test_security.py test_contacts.py test_wire.py test_vectors.py test_core_parity.py

SODIUM = $(shell brew --prefix libsodium 2>/dev/null)
LLVM   = $(shell brew --prefix llvm 2>/dev/null)

.PHONY: install-dev test cov lint sec fuzz all core parity asan fuzz-cpp

install-dev:
	$(BIN)/pip install -r requirements.txt -r requirements-dev.txt

test:
	$(PY) -m pytest -q

cov:
	$(PY) -m pytest -q --cov=. --cov-report=term-missing

lint:
	$(BIN)/ruff check .

sec:
	$(BIN)/bandit -q --severity-level medium -s B101 $(SRC)
	$(BIN)/pip-audit || true
	$(BIN)/detect-secrets scan $(SRC) $(TESTS) > /dev/null && echo "detect-secrets: no secrets found"

fuzz:
	$(PY) fuzz_parser.py

all: test sec fuzz
	@echo "== ALL CHECKS PASSED =="

# ---- Phase 3: C++ core ----
core:                        ## build the C++ extension (needs libsodium + pybind11)
	$(PY) setup.py build_ext --inplace

parity: core                 ## prove the C++ core matches the Python reference
	$(PY) test_core_parity.py

asan:                        ## build+run the parser under AddressSanitizer + UBSan (Apple clang)
	@mkdir -p build
	clang++ -std=c++17 -g -arch arm64 -fsanitize=address,undefined -fno-omit-frame-pointer \
	  -I cpp -I $(SODIUM)/include cpp/core.cpp cpp/asan_test.cpp \
	  -L $(SODIUM)/lib -lsodium -o build/asan_test
	./build/asan_test

fuzz-cpp:                    ## build+run the libFuzzer target (needs: brew install llvm)
	@mkdir -p build
	$(LLVM)/bin/clang++ -std=c++17 -O1 -g -arch arm64 -fsanitize=fuzzer,address,undefined \
	  -I cpp -I $(SODIUM)/include cpp/core.cpp cpp/fuzz_frame.cpp \
	  -L $(SODIUM)/lib -lsodium -o build/fuzz_frame
	./build/fuzz_frame -runs=1000000
