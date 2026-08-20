# Coding Style & Security Standard

This document defines the strict coding, architecture, and security conventions used in this repository. It enforces defense-grade POSIX compliance and memory safety.

## Formatting

*   All C code must be formatted using `clang-format` with the `LLVM` style.
*   Prefer compact guard clauses without braces for one-line early returns.

## Naming Conventions & Namespace Hygiene

*   Use `snake_case` for functions and variables.
*   Use predicate-style names for boolean functions (`*_is_*`, `*_check_*`).
*   Use `UPPER_SNAKE_CASE` for macros and constants.
*   Use opaque structs for public data structures when encapsulation is needed:
    *   Forward declare in header.
    *   Define internals in `.c`.

## Header and Include Conventions

*   Use include guards in every header.
*   End include guards with a trailing comment (`#endif /* NAME_H */`).
*   Typical include order in `.c` files:
    1.  Matching local header (`"module.h"`).
    2.  Standard library headers.
    3.  Project headers (`<...>`).

## API Documentation & Threat Modeling

*   Put a short block comment directly above each public declaration in headers.
*   Document explicit ownership rules when returning allocated memory (e.g., `Caller must free the returned string`).
*   **Security Documentation:** Every public API comment must explicitly document buffer sizes, trust boundaries (is input sanitized?), and POSIX side-effects (does this function `fork` or mutate process state?).

## Error Handling and Control Flow
*   Validate inputs early and return fast on invalid state.
*   **Fail-Closed Posture:** Do not attempt to recover from system-level allocation or execution failures. If `malloc()`, `fork()`, or `execvp()` fails, log the error to `stderr` and aggressively terminate (`exit(EXIT_FAILURE)`).
*   Prefer one cleanup label for multi-step parsing/allocation flows where needed.

## Comments
*   Keep comments to a minimum. The code must speak for itself in 99% of cases.
*   Prefer this style for block documentation comments:
    ```c  
    /* Returns a string describing the preemptive set of a cell
    * Caller must free the returned string */
    ```

## Memory and Resource Management

*   Every allocation must have a clear owner.
*   **Zeroization:** Any buffer handling sensitive input, credentials, or parsed execution arguments must be securely zeroized (e.g., `explicit_bzero`) before being freed.
*   Free partial allocations on intermediate failure paths.
*   Close files and file descriptors on all return paths after successful open.

## Python (Tooling Scripts)

*   Use `snake_case` for functions and variables, `UPPER_SNAKE_CASE` for module-level constants, matching the C convention.
*   **Strong typing, no exceptions:** every function signature carries full parameter and return type annotations, including `-> None`. 
*   Use built-in generics (`list[str]`, `dict[str, int]`)
*   Prefer `pathlib.Path` over string paths; module-level path constants are computed once from `Path(__file__).resolve()`, never hardcoded.
*   Structure a standalone script as `def main() -> int:` returning a process exit code, called from `if __name__ == "__main__": sys.exit(main())`. No top-level executable statements outside `main()`.
*   No list/dict/set comprehensions, generator expressions, or other one-line idioms in place of a loop. Write the `for` loop. A reader should not need to know Python-specific syntax tricks to follow the logic.
*   Keep comments to a minimum, same rule as C: the code should speak for itself.