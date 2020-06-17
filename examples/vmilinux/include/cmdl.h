//
// Copyright (C) 2020 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef VMI_CMDL_H
#define VMI_CMDL_H

#include <vector>
#include <iostream>
#include <string>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <memory>
#include <string.h>

namespace svmi
{

class cmdl
{

public:
    //
    cmdl(const std::string &str, const char delim = ',', const std::string &key = "vmi=")
        : m_cmdline{str}, m_args{}
    {
        if (str == "") {
            m_argv.push_back(nullptr);
            return;
        }

        if (int pos = str.find(key); pos != std::string::npos) {
            pos += key.size();
            char *tmp;
            std::string tmp_str(str);
            char *arg = strtok_r(const_cast<char *>(tmp_str.data() + pos), &delim, &tmp);
            while (arg) {
                if (arg[0] == ' ') {
                    break;
                }
                m_args.push_back(arg);
                arg = strtok_r(NULL, &delim, &tmp);
            }
        }
        else {
            return;
        }

        m_argv.resize(m_args.size() + 1);
        std::transform(m_args.begin(), m_args.end(), m_argv.begin(), [](const std::string & arg) {
            return const_cast<char *>(arg.data());
        });
        m_argv.back() = nullptr;
    }

    char *
    file() const noexcept
    {
        return m_argv[0];
    }

    int
    argc() const noexcept
    {
        return m_args.size();
    }

    char **
    argv() const noexcept
    {
        return const_cast<char **>(m_argv.data());
    }

    std::unique_ptr<std::string>
    to_string() const noexcept
    {
        auto str = std::make_unique<std::string>("");
        std::for_each(m_args.begin(), m_args.end(), [&](const std::string & arg) {
            *str += (arg + " ");
        });
        str->pop_back();
        return str;
    }

    const std::string
    kernel_cmdline() const noexcept
    {
        return m_cmdline;
    }

    void
    add_arg0(const std::string &arg0)
    {
        m_args.insert(m_args.begin(), arg0);

        // Pointers might now be invalid. Need to recompute argv.
        m_argv.resize(m_args.size() + 1);
        std::transform(m_args.begin(), m_args.end(), m_argv.begin(), [](const std::string & arg) {
            return const_cast<char *>(arg.data());
        });
        m_argv.back() = nullptr;
    }

private:
    const std::string &m_cmdline;
    std::vector<std::string> m_args;

    std::vector<char *> m_argv;
};

}

#endif
