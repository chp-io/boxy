//
// Copyright (C) 2019 Assured Information Security, Inc.
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

#pragma GCC diagnostic ignored "-Wunused-result"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <time.h>

extern "C" uint64_t sse_test(uint64_t);

int main(void)
{
    srand(time(0));
    mount("proc", "/proc", "proc", 0, "");

    freopen("/dev/ttyprintk", "w", stdout);
    freopen("/dev/ttyprintk", "w", stderr);

    if (fork() == 0) {
        int64_t val{rand() % 10};
        printf("running sse test with val: %ld\n", val);
        while (1) {
            if (sse_test(val) != val) {
                asm("hlt");
            }
        }
    }
    else {
        wait(NULL);
    }
}

