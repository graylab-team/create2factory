#!/bin/bash
nvcc -I../lib/vanity-eth-address/src finder.cu -o finder -O3 -Xptxas -v -Xcompiler -static-libgcc -Xcompiler -static-libstdc++ -gencode arch=compute_52,code=compute_52