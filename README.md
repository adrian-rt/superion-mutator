Superion is a grammar mutator for AFLPlusPlus 


Implementation details.

The AFLplusplus API the has been implemented in js_parser/TreeMutation.cpp.  This can be used to fuzz various languages such as javascript/php/jerryscript etc. See the Superion for more details, https://github.com/zhunki/Superion/ .



Building

In order to build the following steps are neccesary.

 - Download AFLplusplus from the github repository:
   `git clone https://github.com/AFLplusplus/AFLplusplus`
 - build AFLplusplus by installing dependencies and executing `make`
 - change the path to your AFLplusplus git repository
 - execute the build.sh script inside this folder


Running 

When you want to fuzz simply set the following env_variables prior to running AFLplusplus as usual:

export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY=~/Downloads/afl++/tree_mutation/js_parser/libTreeMutation.so



