export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc

.PHONY: algorithm protocol-test

algorithm:	
	make -C Algorithm
clean:	
	cd Algorithm/ && make clean && cd ../ 	
test:
	cd Algorithm/ && make test && cd ../

protocol-test:
	mkdir -p build
	$(CXX) tests/protocol_regression.cpp multi_issuer.cpp coordinator_certification.cpp nizk_proof.cpp or_proof.cpp Algorithm/bn_pair.cpp Algorithm/miracl.a -I. -IAlgorithm -std=c++11 -O2 -o build/protocol-regression
	bash -o pipefail -c 'timeout 60s build/protocol-regression 2>&1 | tee build/protocol-test.log'
