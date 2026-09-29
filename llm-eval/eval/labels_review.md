# Label review queue

Confirm or correct each proposed label for the c-secure-build findings. Juliet labels come from the User Guide v1.2 naming rules (sections 4.1 and 8) and are listed at the end for spot checks.

## Labeling policy

1. `atoi` on user input (4 items): TP. atoi has undefined behavior when the value does not fit in an int (C17 7.22.1p1), so a range check after the call is too late (CERT ERR34-C). Juliet's own labels are kept: it labels `goodB2G` atoi FP because it scores only the CWE-190 flaw under test, not the conversion call.
2. Unchecked `strdup` (2 items): FP. The NULL is stored and later handled.
3. Rules that flag every call to a listed API (`raptor-interesting-api-calls`) are labeled by whether the flagged call is itself a defect: TP at the C1 `strcpy` and the C4 `malloc`, FP elsewhere.

Edit `eval/real_label_proposals.json`, then rerun `build_items.py items` to regenerate this file and `items.jsonl`.

| id | file:line | tool | rule | proposed | reason |
|---|---|---|---|---|---|
| c-s-091 | real/vuln_shell.c:29 | Flawfinder | `FF1001` | **TP** | C1: strcpy of the unbounded getline buffer into a 32-byte global. |
| c-s-092 | real/vuln_shell.c:39 | Flawfinder | `FF1016` | **TP** | C2: user-supplied format string passed to printf. |
| c-s-093 | real/vuln_shell.c:46 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-094 | real/vuln_shell.c:51 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-095 | real/vuln_shell.c:53 | Flawfinder | `FF1016` | **FP** | Literal "%s\n" format; the user data is an argument. |
| c-s-096 | real/vuln_shell.c:106 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-097 | real/vuln_shell.c:112 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-098 | real/vuln_shell.c:120 | Flawfinder | `FF1022` | **FP** | getline always NUL-terminates its buffer, so strlen cannot over-read. |
| c-s-099 | real/vuln_shell.c:138 | Flawfinder | `FF1047` | **TP** | TP: atoi has undefined behavior when the value does not fit in an int (C17 7.22.1p1), and the range check runs after the call. CERT ERR34-C; the fix is strtol with errno, endptr and range checks. Juliet labels its goodB2G atoi FP because it scores only the CWE-190 flaw under test. |
| c-s-100 | real/hardened_shell.c:28 | Flawfinder | `FF1019` | **FP** | snprintf bounded by sizeof(last_command) with a literal "%s" format. |
| c-s-101 | real/hardened_shell.c:39 | Flawfinder | `FF1016` | **FP** | Literal "%s\n" format; last_command is an argument. |
| c-s-102 | real/hardened_shell.c:43 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-103 | real/hardened_shell.c:48 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-104 | real/hardened_shell.c:50 | Flawfinder | `FF1016` | **FP** | Literal "%s\n" format; the user data is an argument. |
| c-s-105 | real/hardened_shell.c:106 | Flawfinder | `FF1047` | **TP** | TP: atoi has undefined behavior when the value does not fit in an int (C17 7.22.1p1), and the range check runs after the call. CERT ERR34-C; the fix is strtol with errno, endptr and range checks. Juliet labels its goodB2G atoi FP because it scores only the CWE-190 flaw under test. |
| c-s-106 | real/hardened_shell.c:122 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-107 | real/hardened_shell.c:128 | Flawfinder | `FF1016` | **FP** | printf with a string-literal format and no arguments. |
| c-s-108 | real/hardened_shell.c:136 | Flawfinder | `FF1022` | **FP** | getline always NUL-terminates its buffer, so strlen cannot over-read. |
| c-s-109 | real/hardened_shell.c:19 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | calloc of a constant size, result checked for NULL. |
| c-s-110 | real/hardened_shell.c:19 | Semgrep OSS | `raptor-signed-unsigned-conversion` | **FP** | Both calloc arguments are small positive constants. |
| c-s-111 | real/hardened_shell.c:28 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | snprintf bounded by sizeof(last_command) with a literal "%s" format. |
| c-s-112 | real/hardened_shell.c:32 | Semgrep OSS | `raptor-mismatched-memory-management` | **FP** | history[slot] holds a strdup result or NULL; free matches both. |
| c-s-113 | real/hardened_shell.c:33 | Semgrep OSS | `raptor-unchecked-ret-malloc` | **FP** | A NULL from strdup is stored and later handled: recall_slot checks history[slot] == NULL. |
| c-s-114 | real/hardened_shell.c:58 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | strtok_r with a local save pointer on a NUL-terminated getline buffer. |
| c-s-115 | real/hardened_shell.c:62 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | strtok_r with a local save pointer on a NUL-terminated getline buffer. |
| c-s-116 | real/hardened_shell.c:72 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | fork result is checked for -1 and 0. |
| c-s-117 | real/hardened_shell.c:76 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | execvp of user-typed commands is the shell's purpose; argv is not passed through a shell. |
| c-s-118 | real/hardened_shell.c:106 | Semgrep OSS | `raptor-insecure-api-ato` | **TP** | TP: atoi has undefined behavior when the value does not fit in an int (C17 7.22.1p1), and the range check runs after the call. CERT ERR34-C; the fix is strtol with errno, endptr and range checks. Juliet labels its goodB2G atoi FP because it scores only the CWE-190 flaw under test. |
| c-s-119 | real/hardened_shell.c:144 | Semgrep OSS | `raptor-missing-break-in-switch` | **FP** | The case without break ends in continue, which is intended. |
| c-s-120 | real/hardened_shell.c:144 | Semgrep OSS | `raptor-missing-default-in-switch` | **FP** | The switch covers every value of the enum it dispatches on. |
| c-s-121 | real/hardened_shell.c:160 | Semgrep OSS | `raptor-mismatched-memory-management` | **FP** | input_buffer comes from getline, which allocates with malloc; free is the matching release. |
| c-s-122 | real/hardened_shell.c:162 | Semgrep OSS | `raptor-mismatched-memory-management` | **FP** | history[i] holds strdup results or NULL; free matches both. |
| c-s-123 | real/hardened_shell.c:165 | Semgrep OSS | `raptor-mismatched-memory-management` | **FP** | slot_used comes from calloc; free is the matching release. |
| c-s-124 | real/vuln_shell.c:19 | Semgrep OSS | `raptor-integer-wraparound` | **FP** | HISTORY_SLOTS * sizeof(int) is a compile-time constant (4 * 4); it cannot wrap. |
| c-s-125 | real/vuln_shell.c:19 | Semgrep OSS | `raptor-interesting-api-calls` | **TP** | This malloc is C4's root cause: calloc was needed, the flags are read before being written. |
| c-s-126 | real/vuln_shell.c:29 | Semgrep OSS | `raptor-insecure-api-strcpy-strcat` | **TP** | C1: strcpy of the unbounded getline buffer into a 32-byte global. |
| c-s-127 | real/vuln_shell.c:29 | Semgrep OSS | `raptor-interesting-api-calls` | **TP** | The flagged call is the C1 overflow itself. |
| c-s-128 | real/vuln_shell.c:32 | Semgrep OSS | `raptor-unchecked-ret-malloc` | **FP** | A NULL from strdup is stored and later handled: recall_slot checks history[slot] == NULL. |
| c-s-129 | real/vuln_shell.c:39 | Semgrep OSS | `raptor-format-string-bugs` | **TP** | C2: user-supplied format string passed to printf. |
| c-s-130 | real/vuln_shell.c:62 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | strtok_r with a local save pointer on a NUL-terminated getline buffer. |
| c-s-131 | real/vuln_shell.c:66 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | strtok_r with a local save pointer on a NUL-terminated getline buffer. |
| c-s-132 | real/vuln_shell.c:78 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | fork result is checked for -1 and 0. |
| c-s-133 | real/vuln_shell.c:83 | Semgrep OSS | `raptor-interesting-api-calls` | **FP** | execvp of user-typed commands is the shell's purpose; argv is not passed through a shell. |
| c-s-134 | real/vuln_shell.c:138 | Semgrep OSS | `raptor-insecure-api-ato` | **TP** | TP: atoi has undefined behavior when the value does not fit in an int (C17 7.22.1p1), and the range check runs after the call. CERT ERR34-C; the fix is strtol with errno, endptr and range checks. Juliet labels its goodB2G atoi FP because it scores only the CWE-190 flaw under test. |
| c-s-135 | real/vuln_shell.c:148 | Semgrep OSS | `raptor-mismatched-memory-management` | **FP** | input_buffer comes from getline, which allocates with malloc; free is the matching release. |
| c-s-136 | real/vuln_shell.c:149 | Semgrep OSS | `raptor-mismatched-memory-management` | **FP** | slot_used comes from malloc; free is the matching release. |

## Juliet selection

Pool before selection: 351 TP, 521 FP. Excluded: {'not the target type (TP function)': 1034, 'not the target type (FP function)': 1917, 'function neither bad nor good': 928, 'outside any function': 124}.

| id | file:line | function | rule | label |
|---|---|---|---|---|
| jul-001 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_09.c:43 | `CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_09_bad` | `FF1001` | TP |
| jul-002 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__CWE135_04.c:52 | `CWE122_Heap_Based_Buffer_Overflow__CWE135_04_bad` | `FF1003` | TP |
| jul-003 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_04.c:39 | `badVaSinkB` | `FF1016` | TP |
| jul-004 | juliet/190/CWE190_Integer_Overflow__int_fgets_square_13.c:39 | `CWE190_Integer_Overflow__int_fgets_square_13_bad` | `FF1047` | TP |
| jul-005 | juliet/415/CWE415_Double_Free__malloc_free_int_01.c:34 | `CWE415_Double_Free__malloc_free_int_01_bad` | `raptor-double-free` | TP |
| jul-006 | juliet/416/CWE416_Use_After_Free__malloc_free_int64_t_01.c:41 | `CWE416_Use_After_Free__malloc_free_int64_t_01_bad` | `raptor-use-after-free` | TP |
| jul-007 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memcpy_41.c:28 | `CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memcpy_41_badSink` | `FF1004` | TP |
| jul-008 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_14.c:44 | `CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_14_bad` | `FF1004` | TP |
| jul-009 | juliet/134/CWE134_Uncontrolled_Format_String__char_console_fprintf_65b.c:29 | `CWE134_Uncontrolled_Format_String__char_console_fprintf_65b_badSink` | `FF1017` | TP |
| jul-010 | juliet/190/CWE190_Integer_Overflow__int_connect_socket_multiply_06.c:98 | `CWE190_Integer_Overflow__int_connect_socket_multiply_06_bad` | `FF1047` | TP |
| jul-011 | juliet/415/CWE415_Double_Free__malloc_free_int64_t_18.c:38 | `CWE415_Double_Free__malloc_free_int64_t_18_bad` | `raptor-double-free` | TP |
| jul-012 | juliet/416/CWE416_Use_After_Free__return_freed_ptr_04.c:35 | `helperBad` | `raptor-use-after-free` | TP |
| jul-013 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_66b.c:30 | `CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_66b_badSink` | `FF1005` | TP |
| jul-014 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_11.c:37 | `CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_11_bad` | `FF1005` | TP |
| jul-015 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_file_vfprintf_44.c:39 | `badVaSink` | `raptor-format-string-bugs` | TP |
| jul-016 | juliet/190/CWE190_Integer_Overflow__int_connect_socket_square_12.c:95 | `CWE190_Integer_Overflow__int_connect_socket_square_12_bad` | `FF1047` | TP |
| jul-017 | juliet/416/CWE416_Use_After_Free__return_freed_ptr_11.c:35 | `helperBad` | `raptor-use-after-free` | TP |
| jul-018 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__dest_wchar_t_alloca_cat_54e.c:32 | `CWE121_Stack_Based_Buffer_Overflow__dest_wchar_t_alloca_cat_54e_badSink` | `FF1006` | TP |
| jul-019 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncpy_45.c:32 | `badSink` | `FF1008` | TP |
| jul-020 | juliet/134/CWE134_Uncontrolled_Format_String__char_console_vprintf_53d.c:33 | `badVaSink` | `FF1016` | TP |
| jul-021 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_square_51a.c:105 | `CWE190_Integer_Overflow__int_listen_socket_square_51_bad` | `FF1047` | TP |
| jul-022 | juliet/416/CWE416_Use_After_Free__return_freed_ptr_16.c:35 | `helperBad` | `raptor-use-after-free` | TP |
| jul-023 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_15.c:46 | `CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_15_bad` | `FF1008` | TP |
| jul-024 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_ncpy_53d.c:36 | `CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_ncpy_53d_badSink` | `FF1009` | TP |
| jul-025 | juliet/134/CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_44.c:50 | `badSink` | `FF1017` | TP |
| jul-026 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_add_32.c:104 | `CWE190_Integer_Overflow__int_listen_socket_add_32_bad` | `FF1047` | TP |
| jul-027 | juliet/416/CWE416_Use_After_Free__malloc_free_long_18.c:45 | `CWE416_Use_After_Free__malloc_free_long_18_bad` | `raptor-use-after-free` | TP |
| jul-028 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21.c:47 | `CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21_bad` | `FF1010` | TP |
| jul-029 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_05.c:46 | `CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_05_bad` | `FF1013` | TP |
| jul-030 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_04.c:39 | `badVaSinkB` | `raptor-format-string-bugs` | TP |
| jul-031 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_add_68a.c:107 | `CWE190_Integer_Overflow__int_listen_socket_add_68_bad` | `FF1047` | TP |
| jul-032 | juliet/416/CWE416_Use_After_Free__malloc_free_int_64a.c:43 | `CWE416_Use_After_Free__malloc_free_int_64_bad` | `raptor-use-after-free` | TP |
| jul-033 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21.c:47 | `CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21_bad` | `FF1022` | TP |
| jul-034 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_snprintf_04.c:50 | `CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_snprintf_04_bad` | `FF1022` | TP |
| jul-035 | juliet/134/CWE134_Uncontrolled_Format_String__char_listen_socket_vprintf_12.c:54 | `badVaSinkB` | `FF1016` | TP |
| jul-036 | juliet/190/CWE190_Integer_Overflow__int_fgets_preinc_63a.c:38 | `CWE190_Integer_Overflow__int_fgets_preinc_63_bad` | `FF1047` | TP |
| jul-037 | juliet/416/CWE416_Use_After_Free__malloc_free_long_63a.c:43 | `CWE416_Use_After_Free__malloc_free_long_63_bad` | `raptor-use-after-free` | TP |
| jul-038 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_08.c:51 | `CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_08_bad` | `raptor-insecure-api-strcpy-strcat` | TP |
| jul-039 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_11.c:37 | `CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_11_bad` | `raptor-insecure-api-strcpy-strcat` | TP |
| jul-040 | juliet/134/CWE134_Uncontrolled_Format_String__char_connect_socket_vfprintf_66b.c:54 | `badVaSink` | `FF1017` | TP |
| jul-041 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_preinc_54a.c:103 | `CWE190_Integer_Overflow__int_listen_socket_preinc_54_bad` | `FF1047` | TP |
| jul-042 | juliet/416/CWE416_Use_After_Free__return_freed_ptr_15.c:35 | `helperBad` | `raptor-use-after-free` | TP |
| jul-043 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21.c:47 | `CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21_bad` | `raptor-off-by-one` | TP |
| jul-044 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__CWE135_04.c:37 | `CWE122_Heap_Based_Buffer_Overflow__CWE135_04_bad` | `raptor-integer-wraparound` | TP |
| jul-045 | juliet/134/CWE134_Uncontrolled_Format_String__char_environment_printf_34.c:61 | `CWE134_Uncontrolled_Format_String__char_environment_printf_34_bad` | `raptor-format-string-bugs` | TP |
| jul-046 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_09.c:94 | `goodG2B2` | `FF1001` | FP |
| jul-047 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__CWE135_04.c:186 | `goodG2B2` | `FF1001` | FP |
| jul-048 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_vprintf_10.c:410 | `goodG2B2VaSinkB` | `FF1016` | FP |
| jul-049 | juliet/190/CWE190_Integer_Overflow__int_fgets_preinc_63a.c:79 | `goodB2G` | `FF1047` | FP |
| jul-050 | juliet/416/CWE416_Use_After_Free__malloc_free_long_63a.c:90 | `goodB2G` | `raptor-use-after-free` | FP |
| jul-051 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__dest_wchar_t_declare_cpy_53d.c:49 | `CWE121_Stack_Based_Buffer_Overflow__dest_wchar_t_declare_cpy_53d_goodG2BSink` | `FF1003` | FP |
| jul-052 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__CWE135_61a.c:79 | `goodB2G` | `FF1003` | FP |
| jul-053 | juliet/134/CWE134_Uncontrolled_Format_String__char_console_vfprintf_06.c:232 | `goodG2B2VaSinkB` | `FF1017` | FP |
| jul-054 | juliet/190/CWE190_Integer_Overflow__int_connect_socket_multiply_06.c:178 | `goodB2G1` | `FF1047` | FP |
| jul-055 | juliet/416/CWE416_Use_After_Free__malloc_free_int_64a.c:90 | `goodB2G` | `raptor-use-after-free` | FP |
| jul-056 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__src_char_alloca_cat_16.c:63 | `goodG2B` | `FF1005` | FP |
| jul-057 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_int_memcpy_17.c:60 | `goodG2B` | `FF1004` | FP |
| jul-058 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_listen_socket_fprintf_21.c:363 | `goodG2BSink` | `raptor-format-string-bugs` | FP |
| jul-059 | juliet/190/CWE190_Integer_Overflow__int_fgets_square_13.c:117 | `goodB2G2` | `FF1047` | FP |
| jul-060 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_08.c:100 | `goodG2B2` | `FF1006` | FP |
| jul-061 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_src_char_cat_11.c:88 | `goodG2B2` | `FF1005` | FP |
| jul-062 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_file_printf_13.c:170 | `goodG2B1` | `FF1016` | FP |
| jul-063 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_add_32.c:223 | `goodB2G` | `FF1047` | FP |
| jul-064 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncpy_15.c:79 | `goodG2B1` | `FF1008` | FP |
| jul-065 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_ncpy_64b.c:59 | `CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_ncpy_64b_goodG2BSink` | `FF1008` | FP |
| jul-066 | juliet/134/CWE134_Uncontrolled_Format_String__char_file_vfprintf_63b.c:79 | `goodB2GVaSink` | `FF1017` | FP |
| jul-067 | juliet/190/CWE190_Integer_Overflow__int_connect_socket_square_12.c:253 | `goodB2G` | `FF1047` | FP |
| jul-068 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_alloca_ncpy_41.c:54 | `CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_alloca_ncpy_41_goodG2BSink` | `FF1009` | FP |
| jul-069 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_ncpy_53d.c:53 | `CWE122_Heap_Based_Buffer_Overflow__c_CWE193_wchar_t_ncpy_53d_goodG2BSink` | `FF1009` | FP |
| jul-070 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_file_printf_61a.c:59 | `goodG2B` | `raptor-format-string-bugs` | FP |
| jul-071 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_add_68a.c:206 | `goodB2G` | `FF1047` | FP |
| jul-072 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21.c:88 | `goodG2B1` | `FF1010` | FP |
| jul-073 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE806_wchar_t_memcpy_03.c:66 | `goodG2B1` | `FF1013` | FP |
| jul-074 | juliet/134/CWE134_Uncontrolled_Format_String__char_console_printf_01.c:73 | `goodG2B` | `FF1016` | FP |
| jul-075 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_square_51a.c:202 | `goodB2G` | `FF1047` | FP |
| jul-076 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21.c:86 | `goodG2B1` | `FF1013` | FP |
| jul-077 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__CWE135_04.c:183 | `goodG2B2` | `FF1022` | FP |
| jul-078 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_fprintf_65b.c:61 | `CWE134_Uncontrolled_Format_String__wchar_t_connect_socket_fprintf_65b_goodG2BSink` | `FF1017` | FP |
| jul-079 | juliet/190/CWE190_Integer_Overflow__int_fgets_square_13.c:75 | `goodB2G1` | `FF1047` | FP |
| jul-080 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_memmove_45.c:68 | `goodG2BSink` | `FF1022` | FP |
| jul-081 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__CWE135_31.c:76 | `goodG2B` | `raptor-insecure-api-strcpy-strcat` | FP |
| jul-082 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_console_vprintf_04.c:200 | `goodG2B1VaSinkB` | `raptor-format-string-bugs` | FP |
| jul-083 | juliet/190/CWE190_Integer_Overflow__int_listen_socket_preinc_54a.c:200 | `goodB2G` | `FF1047` | FP |
| jul-084 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_52c.c:45 | `CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cat_52c_goodG2BSink` | `raptor-insecure-api-strcpy-strcat` | FP |
| jul-085 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_memcpy_45.c:78 | `goodG2B` | `raptor-integer-wraparound` | FP |
| jul-086 | juliet/134/CWE134_Uncontrolled_Format_String__wchar_t_console_vfprintf_07.c:92 | `goodB2G1VaSinkG` | `FF1016` | FP |
| jul-087 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_21.c:88 | `goodG2B1` | `raptor-off-by-one` | FP |
| jul-088 | juliet/122/CWE122_Heap_Based_Buffer_Overflow__c_CWE805_char_ncat_08.c:85 | `goodG2B1` | `raptor-off-by-one` | FP |
| jul-089 | juliet/134/CWE134_Uncontrolled_Format_String__char_connect_socket_vfprintf_66b.c:95 | `goodB2GVaSink` | `FF1017` | FP |
| jul-090 | juliet/121/CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_53d.c:52 | `CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_declare_ncpy_53d_goodG2BSink` | `raptor-unterminated-string-strncpy` | FP |
