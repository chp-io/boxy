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

#ifndef VMCALL_VP_EXIT_OP_INTEL_X64_BOXY_H
#define VMCALL_VP_EXIT_OP_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <unordered_set>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class vp_exit_op_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    vp_exit_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vp_exit_op_handler() = default;

public:

    // Should map mv_vp_exit_op_next_event hypercall arguments
    struct event_t {
        uint64_t vpid;
        uint64_t reason;
        uint64_t data0;
        uint64_t data1;
    };

public:

    /// Add Listener For Exit
    ///
    /// Add a vpid listener for an exit reason
    ///
    /// @expects
    /// @ensures
    ///
    /// @param reason the mv_vp_exit_t exit reason.
    /// @param vpid the vpid of the vcpu listening for the exit.
    ///
    /// @return returns true if there is no existing vpid listener for this
    /// reason and the listener was successfully added, false otherwise.
    ///
    bool add_listener_for_exit(uint64_t reason, uint64_t vpid);

    /// Remove Listener For Exit
    ///
    /// Remove a vpid listener for an exit reason
    ///
    /// @expects
    /// @ensures
    ///
    /// @param reason the mv_vp_exit_t exit reason.
    /// @param vpid the vpid of the vcpu listening for the exit.
    ///
    /// @return returns true if an existing vpid listener for this reason was
    /// removed, false otherwise.
    ///
    bool remove_listener_for_exit(uint64_t reason, uint64_t vpid);

    /// Notify Next
    ///
    /// Notify the next listener.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if a listener was notified, false otherwise if none
    /// are left
    ///
    bool notify_next(const event_t &event);

    /// Notify Exit
    ///
    /// Notify the first listener.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if a listener was notified, false otherwise if none
    /// exist.
    ///
    bool notify_exit(const event_t &event);

    /// Listener Handled Exit
    ///
    /// Listener has handled the exit. This function doesn't return as it
    /// world switches and resumes execution.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param advance the vcpu should advance before resuming.
    ///
    void listener_handled_exit(bool advance);

    /// Inject Exit And Run
    ///
    /// Inject an exit event and run.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param event the VM Exit event.
    ///
    void inject_exit_and_run(const event_t &event);

private:

    void next_exit_kernel(vcpu *vcpu);
    void next_exit(vcpu *vcpu);
    void end_of_exit(vcpu *vcpu);
    template <typename T>
    void handle_pending_if_exists(vcpu *vp, const T &ctrl);
    template <typename T>
    bool control_exiting(
        vcpu *vp, vcpu *target, uint64_t allowance_mask, T vm_ctrl);
    void vmread(vcpu *vp, vcpu *target);
    void vmwrite(vcpu *vp, vcpu *target);

    bool wrcr3_handler(vcpu_t *vcpu);

    bool dispatch_no_advance_domU(vcpu *vcpu);
    bool dispatch_domU(vcpu *vcpu);
    bool dispatch_dom0(vcpu *vcpu);

private:

    vcpu *m_vcpu;

    std::queue<event_t> m_exit_event_pending;
    uint8_t m_cpl{};
    uint64_t m_next_timeout{0xFFFFFFFFFFFFFFFFULL};

    std::array<std::pair<std::unordered_set<uint64_t>::iterator,
        std::unordered_set<uint64_t> /*vpids*/>, mv_vp_exit_t_max>
        m_notify_vpids_for_reasons{};

public:

    /// @cond

    vp_exit_op_handler(vp_exit_op_handler &&) = default;
    vp_exit_op_handler &operator=(vp_exit_op_handler &&) = default;

    vp_exit_op_handler(const vp_exit_op_handler &) = delete;
    vp_exit_op_handler &operator=(const vp_exit_op_handler &) = delete;

    /// @endcond

};

}

#endif
