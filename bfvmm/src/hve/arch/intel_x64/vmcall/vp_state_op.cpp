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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vmcall/vp_state_op.h>

namespace boxy::intel_x64
{

vp_state_op_handler::vp_state_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    vcpu->add_vmcall_handler({&vp_state_op_handler::dispatch, this});
}

#define case_reg(name)                                                         \
    case mv_reg_t_ ## name:                                                    \
    reg_val = target->name();                                                  \
    break

#define case_reg2(name0, name1)                                                \
    case mv_reg_t_ ## name0:                                                   \
    reg_val = target->name1();                                                 \
    break

#define case_reg_vmcs(name)                                                    \
    case mv_reg_t_ ## name:                                                    \
    target->load();                                                            \
    reg_val = target->name();                                                  \
    vp->load();                                                                \
    break

#define case_reg_vmcs2(name0, name1)                                           \
    case mv_reg_t_ ## name0:                                                   \
    target->load();                                                            \
    reg_val = target->name1();                                                 \
    vp->load();                                                                \
    break

void
vp_state_op_handler::reg_val(vcpu *vp, vcpu *target)
{
    mv_reg_t reg = static_cast<mv_reg_t>(vp->r12());
    uint64_t reg_val = 0;

    switch (reg) {
            case_reg(rax);
            case_reg(rbx);
            case_reg(rcx);
            case_reg(rdx);
            case_reg(rdi);
            case_reg(rsi);
            case_reg2(r8, r08);
            case_reg2(r9, r09);
            case_reg(r10);
            case_reg(r11);
            case_reg(r12);
            case_reg(r13);
            case_reg(r14);
            case_reg(r15);
            case_reg(rbp);
            case_reg(rsp);
            case_reg(rip);
            case_reg_vmcs(cr0);
            case_reg(cr2);
            case_reg_vmcs(cr3);
            case_reg_vmcs(cr4);
            case_reg(cr8);
            case_reg(dr0);
            case_reg(dr1);
            case_reg(dr2);
            case_reg(dr3);
            // FIXME mv_reg_t_dr4
            // FIXME mv_reg_t_dr5
            case_reg(dr6);
            case_reg_vmcs(dr7);
            case_reg_vmcs(rflags);
            case_reg_vmcs2(es, es_selector);
            case_reg_vmcs2(es_base_addr, es_base);
            case_reg_vmcs(es_limit);
            case_reg_vmcs2(es_attributes, es_access_rights);
            case_reg_vmcs2(cs, cs_selector);
            case_reg_vmcs2(cs_base_addr, cs_base);
            case_reg_vmcs(cs_limit);
            case_reg_vmcs2(cs_attributes, cs_access_rights);
            case_reg_vmcs2(ss, ss_selector);
            case_reg_vmcs2(ss_base_addr, ss_base);
            case_reg_vmcs(ss_limit);
            case_reg_vmcs2(ss_attributes, ss_access_rights);
            case_reg_vmcs2(ds, ds_selector);
            case_reg_vmcs2(ds_base_addr, ds_base);
            case_reg_vmcs(ds_limit);
            case_reg_vmcs2(ds_attributes, ds_access_rights);
            case_reg_vmcs2(fs, fs_selector);
            case_reg_vmcs2(fs_base_addr, fs_base);
            case_reg_vmcs(fs_limit);
            case_reg_vmcs2(fs_attributes, fs_access_rights);
            case_reg_vmcs2(gs, gs_selector);
            case_reg_vmcs2(gs_base_addr, gs_base);
            case_reg_vmcs(gs_limit);
            case_reg_vmcs2(gs_attributes, gs_access_rights);
            case_reg_vmcs2(ldtr, ldtr_selector);
            case_reg_vmcs2(ldtr_base_addr, ldtr_base);
            case_reg_vmcs(ldtr_limit);
            case_reg_vmcs2(ldtr_attributes, ldtr_access_rights);
            case_reg_vmcs2(tr, tr_selector);
            case_reg_vmcs2(tr_base_addr, tr_base);
            case_reg_vmcs(tr_limit);
            case_reg_vmcs2(tr_attributes, tr_access_rights);
            // FIXME: mv_reg_t_gdtr
            case_reg_vmcs2(gdtr_base_addr, gdt_base);
            case_reg_vmcs2(gdtr_limit, gdt_limit);
            // FIXME: mv_reg_t_gdtr_attributes
            // FIXME: mv_reg_t_idtr
            case_reg_vmcs2(idtr_base_addr, idt_base);
            case_reg_vmcs2(idtr_limit, idt_limit);
        // FIXME: mv_reg_t_idtr_attributes

        default:
            vp->set_rax(MV_STATUS_INVALID_PARAMS2);
            return;
    }

    vp->set_r10(reg_val);
    vp->set_rax(MV_STATUS_SUCCESS);
}

#define case_msr_vmcs(msr, name)                                               \
    case msr:                                                                  \
    target->load();                                                            \
    msr_val = vmcs_n::guest_## name ::get();                                   \
    vp->load();                                                                \
    break

void
vp_state_op_handler::msr_val(vcpu *vp, vcpu *target)
{
    uint32_t msr = static_cast<uint32_t>(vp->r12());
    uint64_t msr_val = 0;

    switch (msr) {
            case_msr_vmcs(::x64::msrs::ia32_pat::addr, ia32_pat);
            case_msr_vmcs(::intel_x64::msrs::ia32_efer::addr, ia32_efer);
            case_msr_vmcs(::intel_x64::msrs::ia32_fs_base::addr, fs_base);
            case_msr_vmcs(::intel_x64::msrs::ia32_gs_base::addr, gs_base);
            case_msr_vmcs(::intel_x64::msrs::ia32_sysenter_cs::addr, ia32_sysenter_cs);
            case_msr_vmcs(::intel_x64::msrs::ia32_sysenter_eip::addr, ia32_sysenter_eip);
            case_msr_vmcs(::intel_x64::msrs::ia32_sysenter_esp::addr, ia32_sysenter_esp);

        default:
            try {
                msr_val = target->msr(msr);
            }
            catchall({
                bferror_nhex(0, "vp_state_op unhandled msr:", msr);
                vp->set_rax(MV_STATUS_INVALID_PARAMS2);
                return;
            })
    }

    vp->set_r10(msr_val);
    vp->set_rax(MV_STATUS_SUCCESS);
}

bool
vp_state_op_handler::check_and_init_target(vcpu *vp, vcpu **target)
{
    // For now we only allow a domU to target its parent
    // either via MV_VPID_PARENT or with its parent vp id
    switch (vp->r11()) {
        case MV_VPID_SELF:
            vp->set_rax(MV_STATUS_INVALID_VPID_UNSUPPORTED_SELF);
            return false;
        case MV_VPID_PARENT:
            if (vp->is_dom0()) {
                vp->set_rax(MV_STATUS_INVALID_VPID_UNSUPPORTED_PARENT);
                return false;
            }
            *target = vp->parent_vcpu();
            break;
        case MV_VPID_ANY:
            vp->set_rax(MV_STATUS_INVALID_VPID_UNSUPPORTED_ANY);
            return false;
        default:
            if (vp->is_dom0()) {
                // TODO check if is child of current vp
            }
            else if (vp->parent_vcpu()->id() != vp->r11()) {
                vp->set_rax(MV_STATUS_FAILURE_UNSUPPORTED_HYPERCALL);
                return false;
            }

            try {
                *target = get_vcpu(vp->r11());
            }
            catchall({
                vp->set_rax(MV_STATUS_INVALID_VPID_UNKNOWN);
                return false;
            })
    }

    return true;
}

bool
vp_state_op_handler::dispatch(vcpu *vp)
{
    if (mv_hypercall_opcode(vp->rax()) != MV_VP_STATE_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    // Note:
    //
    // A target vcpu is the vcpu on which we want to perform the operation to
    // get or set a register, msr, etc. depending on the hypercall.
    // All vp_state_op hypercalls use r11 (i.e. vpid) to retrieve it as per
    // MicroV specifications.
    vcpu *target;

    switch (mv_hypercall_index(vp->rax())) {
        case MV_VP_STATE_OP_REG_VAL_IDX_VAL:
            if (check_and_init_target(vp, &target)) {
                this->reg_val(vp, target);
            }
            return true;
        case MV_VP_STATE_OP_MSR_VAL_IDX_VAL:
            if (check_and_init_target(vp, &target)) {
                this->msr_val(vp, target);
            }
            return true;
        default:
            break;
    };

    vp->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

}
