#!/bin/bash

cmake ./
make -j16

cd js_parser

for f in *.cpp; do g++ -I ../runtime/src/ -I [Path to AFLplusplus] -c $f -fPIC -std=c++11 -fpermissive -Wattributes; done

g++  -shared -std=c++11 *.o ../dist/libantlr4-runtime.a  -o libTreeMutation.so 

cd ..
