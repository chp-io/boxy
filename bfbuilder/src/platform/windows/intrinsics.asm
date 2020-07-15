;
; Copyright (C) 2019 Assured Information Security, Inc.
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.

.code

;-------------------------------------------------------------------------------
; _mv_cpuid
;-------------------------------------------------------------------------------

_mv_cpuid PROC

        push rbx

        mov r10, rcx
        mov r11, rdx

        mov eax, [rcx]
        cpuid

        mov [r10], eax
        mov [r11], ebx
        mov [r8], ecx
        mov [r9], edx

        pop rbx
        ret

_mv_cpuid ENDP

;-------------------------------------------------------------------------------
; _mv_handle_op_open_handle
;-------------------------------------------------------------------------------

_mv_handle_op_open_handle PROC

        mov r11, rcx

        mov rax, 764D000000010000h
        vmcall

        mov [rdx], r10

        ret
_mv_handle_op_open_handle ENDP

;-------------------------------------------------------------------------------
; _mv_handle_op_close_handle
;-------------------------------------------------------------------------------

_mv_handle_op_close_handle PROC

        mov r10, rcx

        mov rax, 764D000000010001h
        vmcall

        ret

_mv_handle_op_close_handle ENDP

;-------------------------------------------------------------------------------
; _mv_vm_properties_op_set_e820
;-------------------------------------------------------------------------------

_mv_vm_properties_op_set_e820 PROC

        push r12
        push r13

        mov r10, rcx
        mov r11, rdx
        mov r12, r8
        mov r13, r9

        mov rax, 764D000000020006h
        vmcall

        pop r13
        pop r12
        ret

_mv_vm_properties_op_set_e820 ENDP

;-------------------------------------------------------------------------------
; _mv_vm_state_op_gva_to_gpa
;-------------------------------------------------------------------------------

_mv_vm_state_op_gva_to_gpa PROC

        push r12
        push r13

        mov r10, rcx
        mov r11, rdx
        mov r12, r8
        mov r13, r9

        mov rax, 764D000000030008h
        vmcall

        mov r8, [rsp+28h+8*2]
        mov r9, [rsp+30h+8*2]

        mov [r8], r10
        mov [r9], r11

        pop r13
        pop r12
        ret

_mv_vm_state_op_gva_to_gpa ENDP

;-------------------------------------------------------------------------------
; _mv_vm_state_op_map_range
;-------------------------------------------------------------------------------

_mv_vm_state_op_map_range PROC

        push r12
        push r13
        push r14
        push r15

        mov r10, rcx
        mov r11, rdx
        mov r12, r8
        mov r13, r9
        mov r14, [rsp+28h+8*4]
        mov r15, [rsp+30h+8*4]

        mov rax, 764D000000030009h
        vmcall

        pop r15
        pop r14
        pop r13
        pop r12
        ret

_mv_vm_state_op_map_range ENDP

;-------------------------------------------------------------------------------
; _mv_vm_state_op_unmap_range
;-------------------------------------------------------------------------------

_mv_vm_state_op_unmap_range PROC

        push r12
        push r13
        push r14
        push r15

        mov r10, rcx
        mov r11, rdx
        mov r12, r8
        mov r13, r9
        mov r14, [rsp+28h+8*4]
        mov r15, [rsp+30h+8*4]

        mov rax, 764D00000003000Ah
        vmcall

        pop r15
        pop r14
        pop r13
        pop r12
        ret

_mv_vm_state_op_unmap_range ENDP

;-------------------------------------------------------------------------------
; _mv_vp_state_op_reg_val
;-------------------------------------------------------------------------------

_mv_vp_state_op_reg_val PROC

        push r12

        mov r10, rcx
        mov r11, rdx
        mov r12, r8

        mov rax, 764D000000070000h
        vmcall

        mov [r9], r10

        pop r12
        ret

_mv_vp_state_op_reg_val ENDP

;-------------------------------------------------------------------------------
; _mv_vp_state_op_msr_val
;-------------------------------------------------------------------------------

_mv_vp_state_op_msr_val PROC

        push r12

        mov r10, rcx
        mov r11, rdx
        mov r12, r8

        mov rax, 764D000000070004h
        vmcall

        mov [r9], r10

        pop r12
        ret

_mv_vp_state_op_msr_val ENDP

;-------------------------------------------------------------------------------
; !!! WARNING DEPRECATED !!!
;-------------------------------------------------------------------------------

_cpuid_eax PROC

    push rbx

    mov eax, ecx
    mov ecx, 0
    cpuid

    pop rbx
    ret

_cpuid_eax ENDP

_vmcall PROC

    push rbx

    mov rax, rcx
    mov rbx, rdx
    mov rcx, r8
    mov rdx, r9

    vmcall

    pop rbx
    ret

_vmcall ENDP

end
