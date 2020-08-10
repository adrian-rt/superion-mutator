#!/bin/bash
for f in *.cpp; do clang++ -fpermissive -I ../runtime/src/ -I ~/Downloads/afl++ -c $f -fPIC -std=c++11 ; done
clang++ -fpermissive -shared -std=c++11 *.o ../dist/libantlr4-runtime.a  -o libTreeMutation.so
