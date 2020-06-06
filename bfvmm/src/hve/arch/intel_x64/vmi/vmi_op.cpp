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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/emulation/cpuid.h>
#include <hve/arch/intel_x64/vmi/vmi_op.h>

#include <bfhypercall.h>
#include <bfjson.h>

namespace boxy::intel_x64
{

vmi_op_handler::vmi_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{

    // TODO:
    //
    // For now, dom0 is always the target of the introspecting VM
    // and domU is always the introspecting VM.
    // This will change once the vmi policy_op is implemented.

    if (vcpu->is_domU()) {
        vcpu->add_vmcall_handler({&vmi_op_handler::dispatch, this});
        vcpu->add_cpuid_emulator(
            bf_vmi_cpuid_leaf, {&vmi_op_handler::cpuid_vmi, this});
    }
}

// Note:
//
// LibVMI currently makes hypercalls without changing the native ABI, except for setting RAX to the
// hypercall opcode. Therefore, unlike other handlers, we have to follow SystemV's AMD64 ABI for
// the calling convention to handle them.
// As a reminder, the order is: RDI, RSI, RDX, RCX, R8, R9.

void
vmi_op_handler::vmi_op__memmap_ept(vcpu *vcpu)
{
    // Input:
    // RDI = GVA holding the GPA to remap from
    // RSI = GPA of the target to remap to
    // RDX = domid of the target
    //
    // Output:
    // Set RSI to the remapped GPA aligned

    intel_x64::vcpu *target_vcpu;
    if (vcpu->rdx() == 0) {
        target_vcpu = vcpu->parent_vcpu();
    }
    else {
        throw std::runtime_error("domU targets are not yet supported");
    }

    auto [gpa1, unused1] = vcpu->gva_to_gpa(vcpu->rdi());
    uint64_t gpa2 = vcpu->rsi();

    auto &&guest_map = get_domain(vcpu->domid())->ept();

    using namespace ::intel_x64::ept;

    if (guest_map.is_2m(gpa1)) {
        bfdebug_info(10, "vmi_op: guest_map is 2m");
        auto gpa1_2m = bfn::upper(gpa1, pd::from);
        bfvmm::intel_x64::ept::identity_map_convert_2m_to_4k(guest_map, gpa1_2m);
    }

    auto gpa1_4k = bfn::upper(gpa1, pt::from);
    auto gpa2_4k = bfn::upper(gpa2, pt::from);

    vcpu->set_rsi(gpa2_4k);

    auto [pte, unused2] = guest_map.entry(gpa1_4k);

    target_vcpu->load();
    auto [hpa, unused3] = target_vcpu->gpa_to_hpa(gpa2_4k);
    vcpu->load();
    pt::entry::phys_addr::set(pte, hpa);

    // flush EPT tlb, guest TLB doesn't need to be flushed
    // as that translation hasn't changed
    ::intel_x64::vmx::invept_global();
}

void
vmi_op_handler::vmi_op__translate_v2p(vcpu *vcpu)
{
    auto addr = vcpu->rdi();
    auto domid = vcpu->rdx();
    intel_x64::vcpu *_vcpu;

    switch (domid) {
        case 0:
            _vcpu = vcpu->parent_vcpu();
            _vcpu->load();
            break;
        case self:
            _vcpu = vcpu;
            break;
        default:
            throw std::runtime_error("v2p: domU targets are not yet supported");
    }

    auto [gpa, unused] = _vcpu->gva_to_gpa(addr);

    if (domid != self) {
        vcpu->load();
    }

    vcpu->set_rdi(gpa);
}

void
vmi_op_handler::vmi_op__get_register_data(vcpu *vcpu)
{
    uintptr_t addr = vcpu->rdi();
    uint64_t size = vcpu->rsi();

    intel_x64::vcpu *target_vcpu;
    if (vcpu->rdx() == 0) {
        target_vcpu = vcpu->parent_vcpu();
    }
    else {
        throw std::runtime_error("get_regs: domU targets are not yet supported");
    }

    // TODO: Find the target vcpu once policy_op is implemented
    target_vcpu->load();

    json j;
    j["RAX"] = target_vcpu->rax();
    j["RBX"] = target_vcpu->rbx();
    j["RCX"] = target_vcpu->rcx();
    j["RDX"] = target_vcpu->rdx();
    j["R08"] = target_vcpu->r08();
    j["R09"] = target_vcpu->r09();
    j["R10"] = target_vcpu->r10();
    j["R11"] = target_vcpu->r11();
    j["R12"] = target_vcpu->r12();
    j["R13"] = target_vcpu->r13();
    j["R14"] = target_vcpu->r14();
    j["R15"] = target_vcpu->r15();
    j["RBP"] = target_vcpu->rbp();
    j["RSI"] = target_vcpu->rsi();
    j["RDI"] = target_vcpu->rdi();
    j["RIP"] = target_vcpu->rip();
    j["RSP"] = target_vcpu->rsp();
    j["CR0"] = target_vcpu->cr0();
    j["CR2"] = target_vcpu->cr2();
    j["CR3"] = target_vcpu->cr3();
    j["CR4"] = target_vcpu->cr4();
    j["MSR_EFER"] = target_vcpu->ia32_efer();
    j["IDTR_BASE"] = target_vcpu->idt_base();
    // j["GS_BASE"] = target_vcpu->gs_base();
    j["GS_BASE"] = target_vcpu->ia32_kernel_gs_base();
    j["MSR_LSTAR"] = target_vcpu->ia32_lstar();
    j["MSR_CSTAR"] = target_vcpu->ia32_cstar();

    vcpu->load();

    auto omap = vcpu->map_gva_4k<uint8_t>(addr, size);

    auto &&dmp = j.dump();
    std::copy(dmp.begin(), dmp.end(), omap.get());
}

bool
vmi_op_handler::dispatch(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != hypercall_enum_vmi_op) {
        return false;
    }

    try {
        switch (vcpu->rax()) {
            case hypercall_enum_vmi_op__translate_v2p:
                vmi_op__translate_v2p(vcpu);
                break;
            case hypercall_enum_vmi_op__get_registers:
                vmi_op__get_register_data(vcpu);
                break;
            case hypercall_enum_vmi_op__map_pa:
                vmi_op__memmap_ept(vcpu);
                break;
            default:
                break;
        };

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        bfdebug_nhex(0, "vmi_op_handler::dispatch failed", vcpu->rax());
        vcpu->set_rax(FAILURE);
    })

    return true;
}

bool
vmi_op_handler::cpuid_vmi(vcpu_t *vcpu)
{
    auto boxy_vcpu = static_cast<boxy::intel_x64::vcpu *>(vcpu);
    bfalert_ndec(10, "vmi_op: VM Introspection requested from domU id:", boxy_vcpu->domid());
    vcpu->set_rax(bf_vmi_cpuid_rax);
    vcpu->set_rbx(bf_vmi_cpuid_rbx);
    vcpu->set_rcx(bf_vmi_cpuid_rcx);
    vcpu->set_rdx(bf_vmi_cpuid_rdx);
    return vcpu->advance();
}

}
