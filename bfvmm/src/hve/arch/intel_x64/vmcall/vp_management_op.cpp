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
#include <hve/arch/intel_x64/vmcall/vp_management_op.h>

namespace boxy::intel_x64
{

vp_management_op_handler::vp_management_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    vcpu->add_vmcall_handler({&vp_management_op_handler::dispatch, this});
}

void
vp_management_op_handler::pause_vp(vcpu *vp)
{
    vcpu *_vp;

    try {
        if (vp->r11() == MV_VPID_PARENT) {
            _vp = vp->parent_vcpu();
        }
        else {
            _vp = g_vcm->get<vcpu *>(vp->r11());
        }
        _vp->pause();
    } catchall({
        bferror_info(0, "pause vm failed");
        vp->set_rax(MV_STATUS_FAILURE_UNKNOWN);
        return;
    })

    vp->set_rax(MV_STATUS_SUCCESS);
}

void
vp_management_op_handler::resume_vp(vcpu *vp)
{
    vcpu *_vp;

    try {
        if (vp->r11() == MV_VPID_PARENT) {
            _vp = vp->parent_vcpu();
        }
        else {
            _vp = g_vcm->get<vcpu *>(vp->r11());
        }
        _vp->resume();
    } catchall({
        bferror_info(0, "resume vm failed");
        vp->set_rax(MV_STATUS_FAILURE_UNKNOWN);
        return;
    })

    vp->set_rax(MV_STATUS_SUCCESS);
}

bool
vp_management_op_handler::dispatch(vcpu *vcpu)
{
    if (mv_hypercall_opcode(vcpu->rax()) != MV_VP_MANAGEMENT_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    switch (mv_hypercall_index(vcpu->rax())) {
        case MV_VP_MANAGEMENT_OP_PAUSE_VP_IDX_VAL:
            this->pause_vp(vcpu);
            return true;
        case MV_VP_MANAGEMENT_OP_RESUME_VP_IDX_VAL:
            this->resume_vp(vcpu);
            return true;
        default:
            break;
    };

    vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

}
