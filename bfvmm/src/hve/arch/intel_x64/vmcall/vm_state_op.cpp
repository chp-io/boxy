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
#include <hve/arch/intel_x64/vmcall/vm_state_op.h>

namespace boxy::intel_x64
{

vm_state_op_handler::vm_state_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    vcpu->add_vmcall_handler({&vm_state_op_handler::dispatch, this});
}


void
vm_state_op_handler::gva_to_gpa(vcpu *vcpu)
{
    auto vmid{vcpu->r11()};
    auto ptt_gpa{vcpu->r12()};
    auto gva{vcpu->r13()};
    uint64_t gpa = 0;
    uint64_t flags = 0;

    bool is_self = vmid == MV_VMID_SELF || vmid == vcpu->domid();

    if (is_self) {
        gpa = vcpu->gva_to_gpa(gva).first;
    }
    else {
        // TODO: translate gva given ptt_gpa for root and guests
        throw std::runtime_error("gva_to_gpa: non-self is not yet implemented");
    }

    // TODO handle flags;

    if (!is_self) {
        vcpu->load();
    }

    vcpu->set_r10(gpa);
    vcpu->set_r11(flags);

    vcpu->set_rax(MV_STATUS_SUCCESS);
}

void
vm_state_op_handler::map_range(vcpu *vp)
{
    auto src_vmid{vp->r11()};
    auto src_gpa{vp->r12()};
    auto dst_vmid{vp->r13()};
    auto dst_gpa{vp->r14()};
    auto flags{vp->r15()};
    auto size{flags & 0x00000000FFFFFFFF};

    domain *src_vm;
    domain *dst_vm;
    boxy::intel_x64::vcpu *src_vp;
    boxy::intel_x64::vcpu *dst_vp;

    switch (src_vmid) {
        case MV_VMID_ROOT:
            src_vp = vp->parent_vcpu();
            break;
        default:
            throw std::runtime_error(
                "map_range: non-root source is not yet implemented");
    }

    switch (dst_vmid) {
        case MV_VMID_SELF:
            dst_vm = get_domain(vp->domid());
            dst_vp = vp;
            break;
        default:
            throw std::runtime_error(
                "map_range: non-self destination is not yet implemented");
    }

    using namespace ::intel_x64::ept;

    // src REVZ must be zero
    if (bfn::lower(src_gpa, pt::from)) {
        vp->set_rax(MV_STATUS_INVALID_PARAMS2);
        return;
    }

    // dst REVZ must be zero
    if (bfn::lower(dst_gpa, pt::from)) {
        vp->set_rax(MV_STATUS_INVALID_PARAMS4);
        return;
    }

    if (flags & MV_GPA_FLAG_DONATE) {
        // Only the root VM is allowed to donate
        if (vp->is_domU()) {
            vp->set_rax(MV_STATUS_INVALID_PARAMS5);
            return;
        }

        // TODO: Add GPA donate support
        vp->set_rax(MV_STATUS_INVALID_PARAMS5);
        bfdebug_info(0, "map_range: page donation is not yet implemented");
        return;
    }

    if (size == 0) {
        vp->set_rax(MV_STATUS_INVALID_PARAMS5);
        bfdebug_info(0, "map_range: size of 0 was requested.");
        return;
    }

    for (auto _src_gpa = src_gpa, _dst_gpa = dst_gpa;
        _src_gpa < (src_gpa + (size << pt::from));
        _src_gpa += (0x1ULL << pt::from), _dst_gpa += (0x1ULL << pt::from)) {

        try {
            auto [entry, unused0] = dst_vm->ept().entry(dst_gpa);
            auto [hpa, unused1] = src_vp->gpa_to_hpa(src_gpa);
            pt::entry::phys_addr::set(entry, hpa);
            // TODO permission and cache type
        }
        catchall({
            throw std::runtime_error("map_range failed");
        })
    }

    vp->set_rax(MV_STATUS_SUCCESS);
}

bool
vm_state_op_handler::dispatch(vcpu *vcpu)
{
    if (mv_hypercall_opcode(vcpu->rax()) != MV_VM_STATE_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    switch (mv_hypercall_index(vcpu->rax())) {
        case MV_VM_STATE_OP_GVA_TO_GPA_IDX_VAL:
            this->gva_to_gpa(vcpu);
            return true;
        case MV_VM_STATE_OP_MAP_RANGE_IDX_VAL:
            this->map_range(vcpu);
            return true;
        default:
            break;
    };

    vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

}
