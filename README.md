# Superion

Superion is a grammar mutator for AFLPlusPlus.
It can be used to fuzz with specific grammars and make fuzzing more efficient for many targets.
For more information about grammar Fuzzing see https://www.fuzzingbook.org/html/Grammars.html.


## Implementation details.

The AFLplusplus API has been implemented in js_parser/TreeMutation.cpp.  This can be used to fuzz various languages such as javascript/php/jerryscript etc. See the Superion repository for more details, https://github.com/zhunki/Superion/ .



## Building

In order to build the following steps are neccesary.

 - Download AFLplusplus from the github repository:
   ```
   git clone https://github.com/AFLplusplus/AFLplusplus
   ```
 - The current version of AFLplusplus is not supported by this repository. So you have to go into the AFLplusplus repository and change to tag 4.05c by typing
   ```
   git checkout tags/4.05c
   ```
 - build AFLplusplus by installing dependencies and executing
   ```
   make
   ```
 - change the path to your AFLplusplus git repository inside of build.sh
 - execute the build.sh script inside this folder


## Running 

When you want to fuzz simply set the following env_variables prior to running AFLplusplus as usual:

export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY=[PATH to AFLplusplus]/js_parser/libTreeMutation.so



