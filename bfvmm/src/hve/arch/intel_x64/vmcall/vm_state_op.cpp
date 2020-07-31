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

inline std::tuple<domain *, uint64_t, domain *, uint64_t, uint32_t,
       bfvmm::intel_x64::ept::mmap::attr_type,
       bfvmm::intel_x64::ept::mmap::memory_type>
       vm_state_op_handler::map_range_init(vcpu *vp)
{
    auto src_vmid{vp->r11()};
    auto src_gpa{vp->r12()};
    auto dst_vmid{vp->r13()};
    auto dst_gpa{vp->r14()};
    auto flags{vp->r15()};
    auto size{(flags & 0x00000000FFFFFFFF) != 0 ? : 1};

    using namespace bfvmm::intel_x64::ept;

    mmap::attr_type attr = mmap::attr_type::read_only;
    mmap::memory_type cache = mmap::memory_type::write_back;

    domain *src_vm;
    domain *dst_vm;

    switch (src_vmid) {
        case MV_VMID_ROOT:
            src_vm = get_domain(0);
            break;
        default:
            throw std::runtime_error(
                "map_range: non-root source is not yet implemented");
    }

    switch (dst_vmid) {
        case MV_VMID_SELF:
            dst_vm = get_domain(vp->domid());
            break;
        default:
            throw std::runtime_error(
                "map_range: non-self destination is not yet implemented");
    }

    using namespace ::intel_x64::ept;

    // src REVZ must be zero

    if (bfn::lower(src_gpa, pt::from)) {
        vp->set_rax(MV_STATUS_INVALID_PARAMS2);
        return {};
    }

    // dst REVZ must be zero

    if (bfn::lower(dst_gpa, pt::from)) {
        vp->set_rax(MV_STATUS_INVALID_PARAMS4);
        return {};
    }

    // TODO donate and zombie flags

    if (flags & MV_GPA_FLAG_DONATE) {
        // Only the root VM is allowed to donate
        if (vp->is_domU()) {
            vp->set_rax(MV_STATUS_INVALID_PARAMS5);
            return {};
        }

        vp->set_rax(MV_STATUS_INVALID_PARAMS5);
        bfdebug_info(0, "map_range: page donation is not yet implemented");
        return {};
    }

    // Memory access type

    switch ((flags >> 32) & 0x3LLU) {
        case 0: break;
        case 1: attr = mmap::attr_type::read_only; break;
        case 2: attr = mmap::attr_type::write_only; break;
        case 3: attr = mmap::attr_type::read_write; break;
        case 4: attr = mmap::attr_type::execute_only; break;
        case 5: attr = mmap::attr_type::read_execute; break;
        case 6: attr = mmap::attr_type::read_write_execute; break;
        default:
            vp->set_rax(MV_STATUS_INVALID_PARAMS5);
            return {};
    }

    // Cacheability

    switch ((flags >> 35) & 0x7LLU) {
        case 0x00: break;
        case 0x01: cache = mmap::memory_type::uncacheable; break;
        // TODO: case 0x02 uncacheable_minus
        case 0x04: cache = mmap::memory_type::write_combining; break;
        // TODO: case 0x08 write_combining_plus
        case 0x10: cache = mmap::memory_type::write_through; break;
        case 0x20: cache = mmap::memory_type::write_back; break;
        case 0x40: cache = mmap::memory_type::write_protected; break;
        default:
            vp->set_rax(MV_STATUS_INVALID_PARAMS5);
            return {};
    }

    return {src_vm, src_gpa, dst_vm, dst_gpa, size, attr, cache};
}

void
vm_state_op_handler::map_range(vcpu *vp)
{
    auto [src_vm, src_gpa, dst_vm, dst_gpa, size, attr, cache] =
        map_range_init(vp);

    if ((vp->rax() >> 48) == 0xDEAD) {
        return;
    }

    try {
        dst_vm->share_range(dst_gpa, src_gpa, src_vm->ept(), size, attr, cache);
    }
    catchall({
        throw std::runtime_error("map_range failed");
    })

    vp->set_rax(MV_STATUS_SUCCESS);
}

void
vm_state_op_handler::unmap_range(vcpu *vp)
{
    auto [src_vm, src_gpa, dst_vm, dst_gpa, size, attr, cache] =
        map_range_init(vp);

    if ((vp->rax() >> 48) == 0xDEAD) {
        return;
    }

    try {
        dst_vm->unshare_range(dst_gpa, size, attr, cache);
    }
    catchall({
        throw std::runtime_error("map_range failed");
    })

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
        case MV_VM_STATE_OP_UNMAP_RANGE_IDX_VAL:
            this->unmap_range(vcpu);
            return true;
        default:
            break;
    };

    vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

}
