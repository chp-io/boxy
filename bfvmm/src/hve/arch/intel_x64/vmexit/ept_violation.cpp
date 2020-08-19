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
#include <hve/arch/intel_x64/vmexit/ept_violation.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

ept_violation_handler::ept_violation_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_ept_read_violation_handler({
        &ept_violation_handler::handle_ept_read_violation, this});
    vcpu->add_ept_write_violation_handler({
        &ept_violation_handler::handle_ept_write_violation, this});
    vcpu->add_ept_execute_violation_handler({
        &ept_violation_handler::handle_ept_execute_violation, this});
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
ept_violation_handler::handle_ept_read_violation(vcpu_t *vcpu)
{
    bfignored(vcpu);

    bfdebug_nhex(3, "handle_ept_read_violation: ", m_vcpu->rip());

    if (!m_vcpu->notify_exit({
    m_vcpu->id(),
        mv_vp_exit_t_ept_read_violation,
        m_vcpu->gva_to_gpa(m_vcpu->rip()).first,
        m_vcpu->rip(),
    })) {
        bfdebug_info(0,
                     "EPT read violation is enabled but there is no listener to notify");

        return false;
    }

    // Unreachable
    return false;
}

bool
ept_violation_handler::handle_ept_write_violation(vcpu_t *vcpu)
{
    bfignored(vcpu);

    bfdebug_nhex(3, "handle_ept_read_violation: ", m_vcpu->rip());

    if (!m_vcpu->notify_exit({
    m_vcpu->id(),
        mv_vp_exit_t_ept_write_violation,
        m_vcpu->gva_to_gpa(m_vcpu->rip()).first,
        m_vcpu->rip(),
    })) {
        bfdebug_info(0,
                     "EPT read violation is enabled but there is no listener to notify");

        return false;
    }

    // Unreachable
    return false;
}

bool
ept_violation_handler::handle_ept_execute_violation(vcpu_t *vcpu)
{
    bfignored(vcpu);

    bfdebug_nhex(3, "handle_ept_execute_violation: ", m_vcpu->rip());

    if (!m_vcpu->notify_exit({
    m_vcpu->id(),
        mv_vp_exit_t_ept_execute_violation,
        m_vcpu->gva_to_gpa(m_vcpu->rip()).first,
        m_vcpu->rip(),
    })) {
        bfdebug_info(0,
                     "EPT execute violation is enabled but there is no listener to notify");

        return false;
    }

    // Unreachable
    return false;
}

}
