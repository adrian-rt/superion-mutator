#!/bin/bash
for f in *.cpp; do g++ -I ../runtime/src/ -I ~/Downloads/afl++ -c $f -fPIC -std=c++11; done
g++ -shared -std=c++11 *.o ../dist/libantlr4-runtime.a  -o libTreeMutation.so
