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

#pragma GCC diagnostic ignored "-Wunused-result"

#include <string>
#include <fstream>

#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/reboot.h>

#include <cmdl.h>
#include <file.h>

// Notes:
//
// init.cpp parses the kernel cmdline in /proc/cmdline to create argc, argv and passes it to an
// application's main function. Arguements are given by prefixing them with "vmi=" and seperated
// by a comma. e.g. "vmi=arg0,arg1 ..."
//
// init.cpp can be compiled in two ways. With SVMI_STATIC_INIT defined, init.cpp will call a
// statically linked main and a single application will be running on the guest.
// e.g. "vmi=dom0" will call main with argv[0]="init" argv[1]="dom0"
//
// With SVMI_STATIC_INIT not defined, init.cpp will provide a main function that will execute an
// external application. Here, the first agument of "vmi=" needs to be the path of the executable.
// e.g. "vmi=/bin/vmi-module-list,dom0" will call main with argv[0]="/bin/vmi-module-list" and
// argv[1]="dom0".

// Macros:
//
// SVMI_STATIC_INIT        : if defined, call a linked main otherwise provide main and execute an
//                           external program.

// Macros (mainly for testing):
//
// SVMI_INIT_NO_PROC_MOUNT : don't mount proc.
// SVMI_INIT_NO_PRINTK     : don't redirect output to the kernel ring buffer.
// SVMI_CMDLINE_PATH       : define a file path instead of /proc/cmdline for testing.

#ifndef SVMI_CMDLINE_PATH
#define SVMI_CMDLINE_PATH "/proc/cmdline"
#endif

int main(int argc, char **argv);

namespace svmi
{

class pre_main
{
public:
    pre_main()
    {

#ifndef SVMI_INIT_NO_PROC_MOUNT
        mount("proc", "/proc", "proc", 0, "");
#endif

#ifndef SVMI_INIT_NO_PRINTK
        freopen("/dev/ttyprintk", "w", stdout);
        freopen("/dev/ttyprintk", "w", stderr);
#endif

        printf("Init: reached\n");

        auto rawtime = time(0);
        auto loctime = localtime(&rawtime);
        int ret = 0;

        bfn::file f(SVMI_CMDLINE_PATH);
        std::string s(f.data(), f.size());

        // remove line feed
        s.pop_back();

        cmdl cmdl(s);

#ifdef SVMI_STATIC_INIT
        // TODO: Retrieve arg 0 of this process
        cmdl.add_arg0("static-init");
#else
        if (cmdl.argc() == 0) {
            printf("Init: Error: No vmi args found in kernel cmdline.\n");
            printf("Init: cmdline: %s\n", cmdl.kernel_cmdline().data());
            printf("Init: Please use --cmdline='vmi=<vmi_arg0>,<vmi_arg1>'\n");
            printf("Init: e.g. --cmdline='vmi=/bin/vmi-module-list,dom0'\n");
            goto done;
        }
#endif
        printf("Init: Starting %s at %s\n", cmdl.to_string()->data(), asctime(loctime));
        ret = main(cmdl.argc(), cmdl.argv());

done:
        printf("\nInit: return code is %d. Nothing left to do.\n", ret);
        // We don't need to sync since we don't have persistent storage yet
        reboot(RB_HALT_SYSTEM);
    }
};

pre_main do_pre_main;

}

#ifndef SVMI_STATIC_INIT

int
main(int argc, char **argv)
{
    pid_t pid;
    int status;
    int wait_status;

    if ((pid = fork()) == 0) {
        if (execve(argv[0], argv, NULL) == -1) {
            perror("Init: Error: child process execve failed");
            return -1;
        }
    }

    wait_status = waitpid(pid, &status, 0);

    if (!WIFEXITED(status)) {
        printf(
            "Init: %s WEXITSTATUS %d WIFEXITED %d [status %d]\n",
            argv[0],
            WEXITSTATUS(status),
            WIFEXITED(status),
            status);
        perror("Init: waitpid failed");
        return -1;
    }

    return WEXITSTATUS(status);
}

#endif
