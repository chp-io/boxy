/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
        .code64
        .intel_syntax noprefix

/* -------------------------------------------------------------------------- */
/* _mv_cpuid                                                                  */
/* -------------------------------------------------------------------------- */

        .globl  _mv_cpuid
        .type   _mv_cpuid, @function
_mv_cpuid:
        push rbx

        mov r10, rdx
        mov r11, rcx

        mov eax, [rdi]
        cpuid

        mov [rdi], eax
        mov [rsi], ebx
        mov [r10], ecx
        mov [r11], edx

        pop rbx
        ret
        .size _mv_cpuid, .-_mv_cpuid

/* -------------------------------------------------------------------------- */
/* _mv_handle_op_open_handle                                                  */
/* -------------------------------------------------------------------------- */

        .globl  _mv_handle_op_open_handle
        .type   _mv_handle_op_open_handle, @function
_mv_handle_op_open_handle:

        mov r11, rdi

        mov rax, 0x764D000000010000
        vmcall

        mov [rsi], r10

        ret
        .size _mv_handle_op_open_handle, .-_mv_handle_op_open_handle

/* -------------------------------------------------------------------------- */
/* _mv_handle_op_close_handle                                                 */
/* -------------------------------------------------------------------------- */

        .globl  _mv_handle_op_close_handle
        .type   _mv_handle_op_close_handle, @function
_mv_handle_op_close_handle:

        mov r10, rdi

        mov rax, 0x764D000000010000
        vmcall

        ret
        .size _mv_handle_op_close_handle, .-_mv_handle_op_close_handle

/* -------------------------------------------------------------------------- */
/* _mv_vm_properties_op_set_e820                                              */
/* -------------------------------------------------------------------------- */

        .globl  _mv_vm_properties_op_set_e820
        .type   _mv_vm_properties_op_set_e820, @function
_mv_vm_properties_op_set_e820:

        push r12
        push r13

        mov r10, rdi
        mov r11, rsi
        mov r12, rdx
        mov r13, rcx

        mov rax, 0x764D000000020006
        vmcall

        pop r13
        pop r12
        ret
        .size _mv_vm_properties_op_set_e820, .-_mv_vm_properties_op_set_e820

/* -------------------------------------------------------------------------- */
/* !!! WARNING DEPRECATED !!!                                                 */
/* -------------------------------------------------------------------------- */

        .globl  _cpuid_eax
        .type   _cpuid_eax, @function
_cpuid_eax:
        push rbx

        mov eax, edi
        mov ecx, 0
        cpuid

        pop rbx
        ret
        .size _cpuid_eax, .-_cpuid_eax



        .globl  _vmcall
        .type   _vmcall, @function
_vmcall:
        push rbx

        mov r9, rdx
        mov r8, rcx

        mov rax, rdi
        mov rbx, rsi
        mov rcx, r9
        mov rdx, r8

        vmcall

        pop rbx
        ret
        .size _vmcall, .-_vmcall
