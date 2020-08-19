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
#include <hve/arch/intel_x64/vmcall/vp_exit_op.h>

namespace boxy::intel_x64
{

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

constexpr auto vm_control_max = 32ULL;
struct vm_control_t {
    char const *const name;
    void (*const enable)(void);
    void (*const disable)(void);
    void (*const default_handler)(vcpu *vp);
    uint64_t /*enum mv_vp_exit_t*/ exit;
};

namespace ec = vmcs_n::primary_processor_based_vm_execution_controls;
namespace se = vmcs_n::secondary_processor_based_vm_execution_controls;

constexpr const uint64_t primary_allowance_mask =
    ec::cr3_load_exiting::mask |
    ec::monitor_trap_flag::mask;

constexpr const uint64_t secondary_allowance_mask =
    se::ept_violation_ve::mask;

constexpr const vm_control_t primary_vm_controls[vm_control_max] = {
    [ec::cr3_load_exiting::from] = {
        .name = ec::cr3_load_exiting::name,
        .enable = ec::cr3_load_exiting::enable,
        .disable = ec::cr3_load_exiting::disable,
        .default_handler = [](vcpu * vp){ vp->advance(); },
        .exit = mv_vp_exit_t_cr3_load_exiting,
    },
    [ec::monitor_trap_flag::from] = {
        .name = ec::monitor_trap_flag::name,
        .enable = ec::monitor_trap_flag::enable,
        .disable = ec::monitor_trap_flag::disable,
        .default_handler = [](vcpu * vp){ },
        .exit = mv_vp_exit_t_monitor_trap_flag,
    }
};

constexpr const vm_control_t secondary_vm_controls[vm_control_max] = {
    [se::ept_violation_ve::from] = {
        .name = se::ept_violation_ve::name,
        .enable = se::ept_violation_ve::enable,
        .disable = se::ept_violation_ve::disable,
        .default_handler = [](vcpu * vp){ },
        .exit = mv_vp_exit_t_ept_read_violation, // hack, fixme
    }
};

constexpr const vm_control_t exit_to_vm_control[mv_vp_exit_t_max] = {
    [mv_vp_exit_t_cr3_load_exiting] =
    primary_vm_controls[ec::cr3_load_exiting::from],
    [mv_vp_exit_t_monitor_trap_flag] =
    primary_vm_controls[ec::monitor_trap_flag::from],
    [mv_vp_exit_t_ept_read_violation] =
    primary_vm_controls[ec::monitor_trap_flag::from],
    [mv_vp_exit_t_ept_write_violation] =
    primary_vm_controls[ec::monitor_trap_flag::from],
    [mv_vp_exit_t_ept_execute_violation] =
    primary_vm_controls[ec::monitor_trap_flag::from],
};

//------------------------------------------------------------------------------
// Implementation
//------------------------------------------------------------------------------

vp_exit_op_handler::vp_exit_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{

    if (vcpu->is_domU()) {
        vcpu->add_vmcall_handler({&vp_exit_op_handler::dispatch_domU, this});
        vcpu->add_vmcall_no_advance_handler(
        {&vp_exit_op_handler::dispatch_no_advance_domU, this});
    }
    else {
        vcpu->add_vmcall_handler({&vp_exit_op_handler::dispatch_dom0, this});
    }
}

//------------------------------------------------------------------------------
// VMCall Handlers
//------------------------------------------------------------------------------

void
vp_exit_op_handler::next_exit_kernel(vcpu *vcpu)
{
    // Notes:
    //
    // When exit events are setup from the kernel, exits are injected as virtual
    // interrupts as soon as they arrive.
    //
    // This means that when this hypercall is made, we are assuming a virtual
    // interrupt was previously injected due to an exit event, so we should be
    // holding a pending event here.
    //
    // Also, in this context we ignore the timeout flag.

    bfdebug_info(4, "next_exit_kernel: start");

    if (m_exit_event_pending.empty()) {
        // Note:
        //
        throw std::runtime_error(
            "next_event: Asked for an exit event but we have none pending");
    }

    auto &event = m_exit_event_pending.front();

    // Notify event
    vcpu->set_r10(event.vpid);
    vcpu->set_r11(event.reason);
    vcpu->set_r12(event.data0);
    vcpu->set_r13(event.data1);
    vcpu->advance();

    vcpu->set_rax(MV_STATUS_SUCCESS);
    bfdebug_info(4, "next_exit_kernel: end");
}

void
vp_exit_op_handler::next_exit(vcpu *vcpu)
{
    // Notes:
    //
    // This hypercall can be made from the kernel or from userspace.
    //
    // - Kernel: Please read next_exit_kernel notes above
    //
    // - Userspace: We may or may not have an event when called from userspace.
    // If we don't have an event, we return to host without advancing this
    // vmcall causing it to be made again when scheduled execute again.
    // If we have an event pending, resuming the guest handling this exit will
    // cause it to call this hypercall again, in which case we can finally
    // return the exit event. Also note that we are executing in the context of
    // the event (i.e. not bfexec) when resuming the vcpu where the event
    // happened.
    //
    // If we don't have an event pending, it means that the host is in
    // bfexec context, otherwise we are in the context of the event.

    if (m_cpl == 0) {
        next_exit_kernel(vcpu);
        return;
    }

    uint64_t flags{vcpu->r11()};

    bool has_timed_out = m_exit_event_pending.empty()
                         && m_next_timeout != 0xFFFFFFFFFFFFFFFFULL;

    bool is_first_call = m_exit_event_pending.empty()
                         && m_next_timeout == 0xFFFFFFFFFFFFFFFFULL;

    if (flags & MV_VP_EXIT_OP_NEXT_EXIT_FLAGS_HAS_TIMEOUT) {
        m_next_timeout = (vcpu->r11() >> 32) * 1000000; // ms to ns
    }
    else {
        m_next_timeout = 0xFFFFFFFFFFFFFFFFULL;
    }

    if (has_timed_out) {
        bfdebug_info(4, "next_exit: timeout");

        vcpu->set_r11(mv_vp_exit_t_timeout);
        vcpu->advance();

        vcpu->set_rax(MV_STATUS_SUCCESS);
        return;
    }

    if (is_first_call) {
        bfdebug_info(4, "next_exit: no pending events");

        if (m_next_timeout == 0xFFFFFFFFFFFFFFFFULL) {
            vcpu->parent_vcpu()->load();
            vcpu->parent_vcpu()->return_continue();
        }
        else {
            vcpu->parent_vcpu()->load();
            vcpu->parent_vcpu()->return_yield(m_next_timeout);
        }

        // Unreachable

        return;
    }

    auto &event = m_exit_event_pending.front();

    // Notify event
    vcpu->set_r10(event.vpid);
    vcpu->set_r11(event.reason);
    vcpu->set_r12(event.data0);
    vcpu->set_r13(event.data1);
    vcpu->advance();

    vcpu->set_rax(MV_STATUS_SUCCESS);
    bfdebug_info(4, "next_exit: notifying event");
}

void
vp_exit_op_handler::end_of_exit(vcpu *vcpu)
{
    // Notes:
    //
    // This hypercall is used to notify that the caller has processed the event
    // and is telling us how we should proceed.
    //
    // This hypercall comes paired with next_exit and should always be made
    // with the exception of a timeout. When a timeout occured, this hypercall
    // should not be called.

    // Flags:
    // - bit 0: if set, current event was processed otherwise try next handler
    // - bit 1: if set, should advance the vcpu that originated the event
    const uint64_t was_handled_mask  = 0x1ULL << 0ULL;
    const uint64_t should_advance_mask = 0x1ULL << 1ULL;

    uint64_t flags{vcpu->r11()};

    if (GSL_UNLIKELY(m_exit_event_pending.empty())) {
        vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN);
        bfdebug_info(0, "end_of_exit: no pending event found");
        return;
    }

    auto event = m_exit_event_pending.front();
    boxy::intel_x64::vcpu *origin = get_vcpu(event.vpid);

    m_exit_event_pending.pop();
    vcpu->set_rax(MV_STATUS_SUCCESS);

    if (GSL_LIKELY(flags & was_handled_mask)) {
        bfdebug_info(3, "end_of_exit: handled");
        origin->listener_handled_exit(flags & should_advance_mask);

        // Unreachable
    }
    else {
        bfdebug_info(3,
                     "end_of_exit: guest did not handle exit. Trying next listener");
        origin->notify_next(event);

        // Unreachable
    }
}

template <typename T> inline void
vp_exit_op_handler::handle_pending_if_exists(
    vcpu *origin, const T &ctrl)
{
    if (GSL_LIKELY(m_exit_event_pending.empty())) {
        return;
    }

    auto event = m_exit_event_pending.front();
    m_exit_event_pending.pop();

    // Try to send it the next listener if there is one
    if (!origin->notify_next(event)) {
        // No listener left, recover
        origin->load();
        ctrl.default_handler(origin);
        origin->resume();
        m_vcpu->load();
    }

}

template <typename T> bool
vp_exit_op_handler::control_exiting(
    vcpu *vp,
    vcpu *target,
    uint64_t allowance_mask,
    T /*vm_control_t*/ vm_ctrl)
{
    // Verify allowance
    auto mask{vp->r14()};
    if ((mask & ~allowance_mask) != 0) {
        // A denied field is included in the mask
        for (uint64_t i = 0; i < vm_control_max; i++) {
            if (((1ULL << i) & allowance_mask) == 0 &&
                ((1ULL << i) & mask) != 0) {
                bfdebug_ndec(0, "primary vmm exiting not allowed for field", i);
            }
        }
        vp->set_rax(MV_STATUS_INVALID_PARAMS2);
        return false;
    }

    const auto field{vp->r12()};
    const auto value{vp->r13()};

    target->load();
    auto old_value = ::intel_x64::vm::read(field);

    for (uint64_t i = 0; i < vm_control_max; i++) {
        if ((mask & (1ULL << i)) == 0) {
            continue;
        }
        if (value & (1ULL << i)) {
            vm_ctrl[i].enable();
            bfdebug_subtext(3, "vp_exit_op: enable ",
                            vm_ctrl[i].name, nullptr);
            if (!target->add_listener_for_exit(
                    vm_ctrl[i].exit, vp->id())) {
                vp->load();
                vp->set_rax(MV_STATUS_INVALID_EXIT_ALREADY_LISTENING);
                return false;
            }
        }
        else {
            vm_ctrl[i].disable();
            bfdebug_subtext(3, "vp_exit_op: disable ",
                            vm_ctrl[i].name, nullptr);
            // Note:
            //
            // There could be an event pending by the time we get this.
            // It will need to be handled by its default handler.
            handle_pending_if_exists(target, vm_ctrl[i]);

            if (!target->remove_listener_for_exit(
                    vm_ctrl[i].exit, vp->id())) {
                vp->load();
                vp->set_rax(MV_STATUS_INVALID_EXIT_NO_LISTENER);
                return false;
            }
        }
    }

    vp->load();
    vp->set_r10(old_value);

    return true;
}

void
vp_exit_op_handler::vmread(vcpu *vp, vcpu *target)
{
    const auto field{vp->r12()};

    target->load();
    auto value = ::intel_x64::vm::read(field);
    vp->load();

    vp->set_r10(value);
    vp->set_rax(MV_STATUS_SUCCESS);
}

void
vp_exit_op_handler::vmwrite(vcpu *vp, vcpu *target)
{
    // Notes:
    //
    // We currently use a vpid as the listener to an event. This could be
    // changed to using a handle, once handles are implemented, so that multiple
    // sessions within a vCPU could be listeners.
    //
    // For now, we assume that if this vmcall is made from usermode, we should
    // simply run the guest and wait for a next_event vmcall before returning
    // the event, otherwise we should inject a virtual interrupt.
    // Once the kernel handler is implemented, we should only inject virtual
    // interrupts.

    // TODO: Use handle to differentiate between sessions

    m_cpl = vp->cs_selector() & 0x2ULL;

    try {
        const auto field{vp->r12()};

        using namespace ::vmcs_n;
        // Check if field is a VM exit enable field and add handler for it
        switch (field) {
            case primary_processor_based_vm_execution_controls::addr:
                bfdebug_info(3, "vp_exit_op vmwrite 0x4002");
                if (!control_exiting(
                        vp, target, primary_allowance_mask, primary_vm_controls)) {
                    bfdebug_info(3, "vmwrite: primary exiting failed");
                    return;
                }
                bfdebug_info(3, "vmwrite: primary exiting succeded");
                break;
            case secondary_processor_based_vm_execution_controls::addr:
                bfdebug_info(3, "vp_exit_op vmwrite 0x401E");
                if (!control_exiting(
                        vp, target, secondary_allowance_mask,
                        secondary_vm_controls)) {
                    bfdebug_info(3, "vmwrite: secondary exiting failed");
                    return;
                }
                bfdebug_info(3, "vmwrite: secondary exiting succeded");
                break;
            default:
                bfdebug_info(0, "vp_exit_op vmwrite unhandled field");
                vp->set_rax(MV_STATUS_INVALID_PARAMS2);
                return;
        }

        vp->set_rax(MV_STATUS_SUCCESS);

    }
    catchall({
        vp->load();
        bfdebug_nhex(0, "vp_exit_op vmwrite failed for", vp->r12());
        vp->set_rax(MV_STATUS_FAILURE_UNKNOWN);
        return;
    })
}

// -----------------------------------------------------------------------------
// Exit Notifiers
// -----------------------------------------------------------------------------

bool
vp_exit_op_handler::add_listener_for_exit(uint64_t reason, uint64_t vpid)
{
    // FIXME hack
    if (reason == mv_vp_exit_t_ept_read_violation) {
        if (!add_listener_for_exit(mv_vp_exit_t_ept_write_violation, vpid)) {
            return false;
        }
        if (!add_listener_for_exit(mv_vp_exit_t_ept_execute_violation, vpid)) {
            remove_listener_for_exit(mv_vp_exit_t_ept_write_violation, vpid);
            return false;
        }
    }

    auto &[it, vpids] = m_notify_vpids_for_reasons[reason];
    auto [it1, inserted] = vpids.emplace(vpid);
    if (!inserted) {
        bfdebug_nhex(
            0, "notify_for_exit: vpid is already listening for reason", reason);
        return false;
    }
    it = vpids.begin();

    return true;
}

bool
vp_exit_op_handler::remove_listener_for_exit(uint64_t reason, uint64_t vpid)
{
    auto &[it, vpids] = m_notify_vpids_for_reasons[reason];

    if (vpids.erase(vpid) != 1) {
        bfdebug_info(0, "notify_for_exit: vpid is missing");
        return false;
    }
    it = vpids.begin();

    // FIXME: invalid iterator if events are being processed
    return true;
}

void
vp_exit_op_handler::inject_exit_and_run(const event_t &event)
{
    m_exit_event_pending.push(event);
    if (m_exit_event_pending.size() > 1) {
        // Note:
        //
        // Events should be handled has they happen, mimicking VMX events.
        // We should never be queuing more than one event.
        bferror_ndec(0,
                     "inject_exit_and_run: more than 1 pending event",
                     m_exit_event_pending.size());
        // Trying to recover from here
        exit_to_vm_control[event.reason].default_handler(m_vcpu);
        exit_to_vm_control[event.reason].disable();
        return;
    }
    m_vcpu->load();
    if (m_cpl == 0) {
        bfdebug_info(3, "inject_exit_and_run: injecting virtual interrupt");
        m_vcpu->queue_virtual_interrupt(boxy_virq__exit_event_handler);
    }
    else {
        bfdebug_info(3, "inject_exit_and_run: resuming guest");
    }
    m_vcpu->prepare_for_world_switch();
    m_vcpu->run();
}

bool
vp_exit_op_handler::notify_next(const event_t &event)
{
    try {
        auto &[it, vpids] = m_notify_vpids_for_reasons[event.reason];
        if (++it == vpids.end()) {
            bfdebug_ndec(0,
                         "notify_next: unhandled event by listeners", event.reason);
            return false;
        }
        vcpu *vp = get_vcpu(*it);
        vp->inject_exit_and_run(event);

        // Unreachable
    }
    catchall({
        bfdebug_info(0, "notify_next: failed");
    })

    return false;
}

bool
vp_exit_op_handler::notify_exit(const event_t &event)
{
    try {
        auto &[it, vpids] = m_notify_vpids_for_reasons[event.reason];
        if (vpids.empty()) {
            return false;
        }

        it = vpids.begin();
        vcpu *vp = get_vcpu(*it);

        bfdebug_info(3, "notify_exit: pausing self");
        m_vcpu->pause();
        vp->inject_exit_and_run(event);

        // Unreachable
    }
    catchall({
        bfdebug_info(0, "notify_exit: failed");

    })

    return false;
}

void
vp_exit_op_handler::listener_handled_exit(bool should_advance)
{
    m_vcpu->load();
    if (should_advance) {
        m_vcpu->advance();
    }
    else {
        bfdebug_nhex(0, "listener_handled_exit: not advancing!", m_vcpu->id());
    }
    m_vcpu->resume();

    // Lets not steal more time than we have to
    m_vcpu->prepare_for_world_switch();
    m_vcpu->run();
}

// -----------------------------------------------------------------------------
// VMCall Dispatch
// -----------------------------------------------------------------------------

bool
vp_exit_op_handler::dispatch_no_advance_domU(vcpu *vcpu)
{
    if (mv_hypercall_opcode(vcpu->rax()) != MV_VP_EXIT_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    switch (mv_hypercall_index(vcpu->rax())) {
        case MV_VP_EXIT_OP_NEXT_EXIT_IDX_VAL:
            this->next_exit(vcpu);
            return true;
        default:
            break;
    };

    // Give other vp_exit_op vmcalls an opportunity to be handled
    return false;
}

bool
vp_exit_op_handler::dispatch_domU(vcpu *vcpu)
{
    if (mv_hypercall_opcode(vcpu->rax()) != MV_VP_EXIT_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    switch (mv_hypercall_index(vcpu->rax())) {
        case MV_VP_EXIT_OP_END_OF_EXIT_IDX_VAL:
            this->end_of_exit(vcpu);
            return true;
        case MV_VP_EXIT_OP_VMREAD_IDX_VAL:
            switch (vcpu->r11()) {
                case MV_VPID_PARENT:
                    this->vmread(vcpu, vcpu->parent_vcpu());
                    return true;
                case MV_VPID_SELF:
                    vcpu->set_rax(MV_STATUS_INVALID_PARAMS1);
                    return true;
                default: {
                    try {
                        this->vmread(vcpu, get_vcpu(vcpu->r11()));
                    }
                    catchall({
                        vcpu->set_rax(MV_STATUS_INVALID_PARAMS1);
                    })
                    return true;
                }
            }
        case MV_VP_EXIT_OP_VMWRITE_IDX_VAL:
            switch (vcpu->r11()) {
                case MV_VPID_PARENT:
                    this->vmwrite(vcpu, vcpu->parent_vcpu());
                    return true;
                case MV_VPID_SELF:
                    vcpu->set_rax(MV_STATUS_INVALID_PARAMS1);
                    return true;
                default: {
                    try {
                        this->vmwrite(vcpu, get_vcpu(vcpu->r11()));
                    }
                    catchall({
                        vcpu->set_rax(MV_STATUS_INVALID_PARAMS1);
                    })
                    return true;
                }
            }

        default:
            break;
    };

    vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

bool
vp_exit_op_handler::dispatch_dom0(vcpu *vcpu)
{
    if (mv_hypercall_opcode(vcpu->rax()) != MV_VP_EXIT_OP_VAL) {
        return false;
    }

    // TODO: Validate the handle

    switch (mv_hypercall_index(vcpu->rax())) {
        default:
            break;
    };

    vcpu->set_rax(MV_STATUS_FAILURE_UNKNOWN_HYPERCALL);
    return true;
}

}
