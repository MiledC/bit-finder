NVCC     ?= nvcc
# GPU architecture; "native" targets the card in this machine (CUDA 11.6+).
# Override for a specific card, e.g. make ARCH=sm_89
ARCH     ?= native
GROUP    ?= 256
CXX      ?= g++

NVFLAGS  = -O3 -std=c++17 -arch=$(ARCH) -DGROUP=$(GROUP) -Xptxas -O3
CXXFLAGS = -O2 -std=c++17 -Wall -Wextra -DGROUP=$(GROUP)

HEADERS = src/common.h src/secp256k1.h src/hash.h src/walk.h src/host.h

all: vanity

vanity: src/main.cu $(HEADERS)
	$(NVCC) $(NVFLAGS) -o $@ src/main.cu

tests/test_cpu: tests/test_cpu.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -o $@ tests/test_cpu.cpp

# Runs on any machine, no GPU needed.
test: tests/test_cpu
	./tests/test_cpu
	python3 tests/ref.py ./tests/test_cpu

# Real GPU searches, every match checked with libsecp256k1 (needs coincurve).
e2e: vanity
	tests/e2e.sh $(PY)

PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

clean:
	rm -f vanity tests/test_cpu

.PHONY: all test e2e clean
