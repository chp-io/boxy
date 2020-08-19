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
#include <hve/arch/intel_x64/vmexit/monitor_trap.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

monitor_trap_handler::monitor_trap_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_monitor_trap_handler(
    {&monitor_trap_handler::handle_monitor_trap, this});
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
monitor_trap_handler::handle_monitor_trap(vcpu_t *vcpu)
{
    // Bareflank turns off MTF on the first exit. We turn it back on here to
    // be consistent with VMX and let listeners (non-vmx-root handlers)
    // use the vmwrite hypercall to turn it off if they want to.
    vcpu->enable_monitor_trap_flag();

    bfdebug_nhex(3, "handle_monitor_trap: ", m_vcpu->rip());

    if (!m_vcpu->notify_exit({
    m_vcpu->id(),
        mv_vp_exit_t_monitor_trap_flag,
        m_vcpu->gva_to_gpa(m_vcpu->rip()).first,
        m_vcpu->rip(),
    })) {
        bfdebug_info(0,
                     "MTF exiting is enabled but there is no listener to notify");
        using namespace vmcs_n::primary_processor_based_vm_execution_controls;
        monitor_trap_flag::disable();

        return m_vcpu->advance();
    }

    // Unreachable
    return false;
}


}
