// The one header bSecured force-includes into every source file of the target.
//
// It is compiled once per translation unit, so anything heavy
// here multiplies the target's compile cost and its name-collision surface. All
// it does is make sure the guard thread is started. The guard itself lives in a
// static library that is linked, not included.
#pragma once

namespace bsecured
{
    // Starts the background guard on the first call; later calls do nothing.
    // Never throws and never blocks: safe to call from a static initializer.
    void ensure_started() noexcept;
}  // namespace bsecured

namespace
{
// Force-including this header into N source files places N copies of this
// initializer, one per file. Each calls ensure_started(), which starts the
// guard exactly once (std::call_once).
[[maybe_unused]] const bool bsecured_guard_autostart = (bsecured::ensure_started(), true);
}  // namespace
