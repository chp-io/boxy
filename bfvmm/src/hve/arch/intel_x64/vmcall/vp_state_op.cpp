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
        reg_val = _vp->name();                                                 \
        break

#define case_reg2(name0, name1)                                                \
    case mv_reg_t_ ## name0:                                                   \
        reg_val = _vp->name1();                                                \
        break

#define case_reg_vmcs(name)                                                    \
    case mv_reg_t_ ## name:                                                    \
        _vp->load();                                                           \
        reg_val = _vp->name();                                                 \
        vp->load();                                                            \
        break

#define case_reg_vmcs2(name0, name1)                                           \
    case mv_reg_t_ ## name0:                                                   \
        _vp->load();                                                           \
        reg_val = _vp->name1();                                                \
        vp->load();                                                            \
        break

void
vp_state_op_handler::reg_val(vcpu *vp)
{
    vcpu *_vp;

    // For now we only allow a domU to target its parent
    // either via MV_VPID_PARENT or with its parent vp id
    switch (vp->r11()) {
        case MV_VPID_SELF:
            vp->set_rax(MV_STATUS_INVALID_VPID_UNSUPPORTED_SELF);
            return;
        case MV_VPID_PARENT:
            if (vp->is_dom0()) {
                vp->set_rax(MV_STATUS_INVALID_VPID_UNSUPPORTED_PARENT);
                return;
            }
            _vp = vp->parent_vcpu();
            break;
        case MV_VPID_ANY:
            vp->set_rax(MV_STATUS_INVALID_VPID_UNSUPPORTED_ANY);
            return;
        default:
            if (vp->is_dom0()) {
                // TODO check is child of current vp
            }
            else if (vp->parent_vcpu()->id() != vp->r11()) {
                vp->set_rax(MV_STATUS_FAILURE_UNSUPPORTED_HYPERCALL);
                return;
            }

            try {
                _vp = get_vcpu(vp->r11());
            }
            catchall({
                vp->set_rax(MV_STATUS_INVALID_VPID_UNKNOWN);
                return;
            })
    }

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

bool
vp_state_op_handler::dispatch(vcpu *vcpu)
{
    if (mv_hypercall_opcode(vcpu->rax()) != MV_VP_STATE_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    switch (mv_hypercall_index(vcpu->rax())) {
        case MV_VP_STATE_OP_REG_VAL_IDX_VAL:
            this->reg_val(vcpu);
            return true;
        default:
            break;
    };

    vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

}
