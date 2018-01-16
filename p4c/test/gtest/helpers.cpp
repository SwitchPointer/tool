/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "helpers.h"

#include "frontends/common/applyOptionsPragmas.h"
#include "frontends/common/parseInput.h"
#include "frontends/p4/frontend.h"

namespace detail {

std::string makeP4Source(const char* file, unsigned line,
                         P4Headers headers, const char* rawSource) {
    std::stringstream source;

    // Prepend any requested headers.
    switch (headers) {
        case P4Headers::NONE: break;
        case P4Headers::CORE:
            source << P4CTestEnvironment::get()->coreP4();
            break;
        case P4Headers::V1MODEL:
            source << P4CTestEnvironment::get()->coreP4();
            source << P4CTestEnvironment::get()->v1Model();
            break;
        case P4Headers::PSA:
            source << P4CTestEnvironment::get()->coreP4();
            source << P4CTestEnvironment::get()->psaP4();
            break;
    }

    unsigned lineCount = 0;
    for (auto iter = rawSource; *iter; ++iter) {
        if (*iter == '\n') ++lineCount;
    }

    // Add a #line preprocessor directive, so that any errors generated by the
    // compiler reference the appropriate file and line in the unit test source
    // code. __LINE__ (i.e., @line in this function) refers to the *last* line
    // containing a multiline macro; since we expect this function to be called
    // from a macro that accepts a multiline P4 program in a raw string, we need
    // to subtract the number of lines in the program to get the *first* line of
    // the macro, which is what we need to use in #line to get the correct
    // mapping to the unit test source.
    source << "#line " << (line - lineCount)  << " \"" << file << "\"" << std::endl;
    source << rawSource;

    return source.str();
}

std::string makeP4Source(const char* file, unsigned line, const char* rawSource) {
    return makeP4Source(file, line, P4Headers::NONE, rawSource);
}

}  // namespace detail

/* static */ P4CTestEnvironment* P4CTestEnvironment::get() {
    static P4CTestEnvironment* instance = new P4CTestEnvironment;
    return instance;
}

P4CTestEnvironment::P4CTestEnvironment() {
    auto readHeader = [](const char* filename) {
        std::ifstream input(filename);
        if (!input.good()) {
          throw std::runtime_error(std::string("Couldn't read standard header ")
                                     + filename);
        }

        // Initialize a buffer with a #line preprocessor directive. This ensures
        // that any errors we encounter in this header will reference the
        // correct file and line.
        std::stringstream buffer;
        buffer << "#line 1 \"" << filename << "\"" << std::endl;

        // Read the header into the buffer and return it.
        while (input >> buffer.rdbuf()) continue;
        return buffer.str();
    };

    // XXX(seth): We should find a more robust way to locate these headers.
    _coreP4 = readHeader("p4include/core.p4");
    _v1Model = readHeader("p4include/v1model.p4");
    _psaP4 = readHeader("p4include/psa.p4");
}

namespace Test {

/* static */ boost::optional<FrontendTestCase>
FrontendTestCase::create(const std::string& source,
                         CompilerOptions::FrontendVersion langVersion
                            /* = CompilerOptions::FrontendVersion::P4_16 */) {
    auto* program = P4::parseP4String(source, langVersion);
    if (program == nullptr) {
        std::cerr << "Couldn't parse test case source" << std::endl;
        return boost::none;
    }
    if (::diagnosticCount() > 0) {
        std::cerr << "Encountered " << ::diagnosticCount()
                  << " errors while parsing test case" << std::endl;
        return boost::none;
    }

    P4::P4COptionPragmaParser optionsPragmaParser;
    program->apply(P4::ApplyOptionsPragmas(optionsPragmaParser));
    if (::errorCount() > 0) {
        std::cerr << "Encountered " << ::errorCount()
                  << " errors while collecting options pragmas" << std::endl;
        return boost::none;
    }

    CompilerOptions options;
    options.langVersion = langVersion;
    program = P4::FrontEnd().run(options, program, true);
    if (program == nullptr) {
        std::cerr << "Frontend failed" << std::endl;
        return boost::none;
    }
    if (::errorCount() > 0) {
        std::cerr << "Encountered " << ::errorCount()
                  << " errors while executing frontend" << std::endl;
        return boost::none;
    }

    return FrontendTestCase{program};
}

}  // namespace Test