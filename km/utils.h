namespace utils
{
    uintptr_t swap_process( uintptr_t new_process )
    {
        auto current_thread = ( uintptr_t )KeGetCurrentThread( );

        auto apc_state = *( uintptr_t * )( current_thread + 0x98 );
        auto old_process = *( uintptr_t * )( apc_state + 0x20 );
        *( uintptr_t * )( apc_state + 0x20 ) = new_process;

        auto dir_table_base = *( uintptr_t * )( new_process + 0x28 );
        __writecr3( dir_table_base );

        return old_process;
    }

    uintptr_t resolve_relative_address( uintptr_t instruction, ULONG offset_offset, ULONG instruction_size )
    {
        auto instr = instruction;

        const auto rip_offset = *( PLONG )( instr + offset_offset );

        const auto resolved_addr = instr + instruction_size + rip_offset;

        return resolved_addr;
    }

    void *get_system_information( SYSTEM_INFORMATION_CLASS information_class )
    {
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation( information_class, buffer, size, &size );

        void *info = ExAllocatePoolZero( NonPagedPool, size, 7265746172 );

        if ( !info )
            return nullptr;

        if ( !NT_SUCCESS( ZwQuerySystemInformation( information_class, info, size, &size ) ) )
        {
            ExFreePool( info );
            return nullptr;
        }

        return info;
    }

    uintptr_t get_kernel_module( const char *name )
    {
        const auto to_lower = []( char *string ) -> const char *
        {
            for ( char *pointer = string; *pointer != '\0'; ++pointer )
            {
                *pointer = ( char )( short )tolower( *pointer );
            }

            return string;
        };

        const PRTL_PROCESS_MODULES info = ( PRTL_PROCESS_MODULES )get_system_information( SystemModuleInformation );

        if ( !info )
            return NULL;

        for ( size_t i = 0; i < info->NumberOfModules; ++i )
        {
            const auto &mod = info->Modules[i];

            if ( crt::strcmp( to_lower_c( ( char * )mod.FullPathName + mod.OffsetToFileName ), name ) == 0 )
            {
                const void *address = mod.ImageBase;
                ExFreePool( info );
                return ( uintptr_t )address;
            }
        }

        ExFreePool( info );
        return NULL;
    }

    auto get_kernel_export( const char *module_name, LPCSTR export_name ) -> uintptr_t
    {
        return reinterpret_cast< uintptr_t > ( RtlFindExportedRoutineByName( reinterpret_cast< void * > ( utils::get_kernel_module( module_name ) ), export_name ) );
    }

    void sleep( int ms ) 
    {
        LARGE_INTEGER time;
        time.QuadPart = -( ms ) * 10 * 1000;
        KeDelayExecutionThread( KernelMode, TRUE, &time );
    }

    uintptr_t find_pattern( uintptr_t base, size_t range, const char *pattern, const char *mask )
    {
        const auto check_mask = []( const char *base, const char *pattern, const char *mask ) -> bool
        {
            for ( ; *mask; ++base, ++pattern, ++mask )
            {
                if ( *mask == 'x' && *base != *pattern )
                {
                    return false;
                }
            }

            return true;
        };

        range = range - crt::strlen( mask );

        for ( size_t i = 0; i < range; ++i )
        {
            if ( check_mask( ( const char * )base + i, pattern, mask ) )
            {
                return base + i;
            }
        }

        return NULL;
    }

    uintptr_t find_pattern( uintptr_t base, const char *pattern, const char *mask )
    {
        const PIMAGE_NT_HEADERS headers = ( PIMAGE_NT_HEADERS )( base + ( ( PIMAGE_DOS_HEADER )base )->e_lfanew );
        const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION( headers );

        for ( size_t i = 0; i < headers->FileHeader.NumberOfSections; i++ )
        {
            const PIMAGE_SECTION_HEADER section = &sections[i];

            if ( section->Characteristics & IMAGE_SCN_MEM_EXECUTE )
            {
                const auto match = find_pattern( base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask );

                if ( match )
                {
                    return match;
                }
            }
        }

        return 0;
    }

    uintptr_t find_pattern( uintptr_t module_base, const char* pattern )
    {
        auto pattern_ = pattern;
        uintptr_t first_match = 0;

        if ( !module_base )
        {
            return 0;
        }

        const auto nt = reinterpret_cast< IMAGE_NT_HEADERS * >( module_base + reinterpret_cast< IMAGE_DOS_HEADER * >( module_base )->e_lfanew );

        for ( uintptr_t current = module_base; current < module_base + nt->OptionalHeader.SizeOfImage; current++ )
        {
            if ( !*pattern_ )
            {
                return first_match;
            }

            if ( *( BYTE * )pattern_ == '\?' || *( BYTE * )current == get_byte( pattern_ ) )
            {
                if ( !first_match )
                    first_match = current;

                if ( !pattern_[2] )
                    return first_match;

                if ( *( WORD * )pattern_ == '\?\?' || *( BYTE * )pattern_ != '\?' )
                    pattern_ += 3;

                else
                    pattern_ += 2;
            }
            else
            {
                pattern_ = pattern;
                first_match = 0;
            }
        }

        return 0;
    }

    uintptr_t get_module_handle( uintptr_t pid, LPCWSTR module_name )
    {
        PEPROCESS target_proc;
        uintptr_t base = 0;
        if ( !NT_SUCCESS( PsLookupProcessByProcessId( ( HANDLE )pid, &target_proc ) ) )
            return 0;

        const auto o_process = swap_process( ( uintptr_t )target_proc );

        PPEB peb = PsGetProcessPeb( target_proc );
        if ( !peb )
            goto end;

        if ( !peb->Ldr || !peb->Ldr->Initialized )
            goto end;


        UNICODE_STRING module_name_unicode;
        RtlInitUnicodeString( &module_name_unicode, module_name );
        for ( PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
            list != &peb->Ldr->InLoadOrderModuleList;
            list = list->Flink ) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD( list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
            if ( RtlCompareUnicodeString( &entry->BaseDllName, &module_name_unicode, TRUE ) == 0 ) {
                base = ( uintptr_t )entry->DllBase;
                goto end;
            }
        }

    end:

        swap_process( ( uintptr_t )o_process );

        ObDereferenceObject( target_proc );

        return base;
    }

    bool safe_copy( void* dst, void *src, size_t size )
    {
        SIZE_T bytes = 0;

        if ( MmCopyVirtualMemory( IoGetCurrentProcess( ), src, IoGetCurrentProcess( ), dst, size, KernelMode, &bytes ) == STATUS_SUCCESS && bytes == size )
        {
            return true;
        }

        return false;
    }

    MEMORY_BASIC_INFORMATION query_virtual_memory( void* address )
    {
        MEMORY_BASIC_INFORMATION mbi;
        ZwQueryVirtualMemory( ( HANDLE )-1, address, MemoryBasicInformation, &mbi, sizeof( MEMORY_BASIC_INFORMATION ), 0 );
        return mbi;
    }

    PAGE_INFORMATION get_page_information( void *va, CR3 cr3 )
    {
        ADDRESS_TRANSLATION_HELPER helper;
        UINT32 level;
        PML4E_64 *pml4, *pml4e;
        PDPTE_64 *pdpt, *pdpte;
        PDE_64 *pd, *pde;
        PTE_64 *pt, *pte;

        PAGE_INFORMATION info;

        helper.AsUInt64 = ( uintptr_t )va;

        PHYSICAL_ADDRESS pa;

        pa.QuadPart = cr3.AddressOfPageDirectory << PAGE_SHIFT;

        pml4 = ( PML4E_64 * )MmGetVirtualForPhysical( pa );

        pml4e = &pml4[helper.AsIndex.Pml4];

        info.PML4E = pml4e;

        if ( pml4e->Present == FALSE )
        {
            info.PTE = nullptr;
            info.PDE = nullptr;
            info.PDPTE = nullptr;

            goto end;
        }

        pa.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

        pdpt = ( PDPTE_64 * )MmGetVirtualForPhysical( pa );

        pdpte = &pdpt[helper.AsIndex.Pdpt];

        info.PDPTE = pdpte;

        if ( ( pdpte->Present == FALSE ) || ( pdpte->LargePage != FALSE ) )
        {
            info.PTE = nullptr;
            info.PDE = nullptr;

            goto end;
        }

        pa.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

        pd = ( PDE_64 * )MmGetVirtualForPhysical( pa );

        pde = &pd[helper.AsIndex.Pd];

        info.PDE = pde;

        if ( ( pde->Present == FALSE ) || ( pde->LargePage != FALSE ) )
        {
            info.PTE = nullptr;

            goto end;
        }

        pa.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

        pt = ( PTE_64 * )MmGetVirtualForPhysical( pa );

        pte = &pt[helper.AsIndex.Pt];

        info.PTE = pte;

        return info;

    end:
        return info;
    }

    MDL_INFORMATION allocate_mdl_memory( size_t size )
    {
        MDL_INFORMATION memory;

        PHYSICAL_ADDRESS lower, higher;
        lower.QuadPart = 0;
        higher.QuadPart = 0xffff'ffff'ffff'ffffULL;

        const auto pages = ( size / PAGE_SIZE ) + 1;

        const auto mdl = MmAllocatePagesForMdl( lower, higher, lower, pages * ( uintptr_t )0x1000 );

        if ( !mdl )
        {
            return { 0, 0 };
        }

        const auto mapping_start_address = MmMapLockedPagesSpecifyCache( mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority );

        if ( !mapping_start_address )
        {
            return { 0, 0 };
        }

        if ( !NT_SUCCESS( MmProtectMdlSystemAddress( mdl, PAGE_EXECUTE_READWRITE ) ) )
        {
            return { 0, 0 };
        }

        memory.mdl = mdl;
        memory.va = reinterpret_cast<uintptr_t> ( mapping_start_address );

        return memory;
    }

    void free_mdl_memory( MDL_INFORMATION &memory )
    {
        MmUnmapLockedPages( reinterpret_cast< void * >( memory.va ), memory.mdl );
        MmFreePagesFromMdl( memory.mdl );
        ExFreePool( memory.mdl );
    }

    void* allocate_kernel_memory( const size_t _size, uintptr_t* mdl )
    {
        const auto size = size_align( _size );

        auto memory = allocate_mdl_memory( size );

        while ( memory.va % 0x10000 != 0 )
        {
            free_mdl_memory( memory );
            memory = allocate_mdl_memory( size );
        }

        *mdl = (uintptr_t)memory.mdl;
        return (void*)memory.va;
    }

    bool expose_kernel_memory( const int pid, const uintptr_t kernel_address, const size_t size )
    {
        PEPROCESS process;
        if ( PsLookupProcessByProcessId( ( HANDLE )pid, &process ) == STATUS_SUCCESS )
        {
            const auto o_process = utils::swap_process( ( uintptr_t )process );

            CR3 cr3 { };
            cr3.Flags = __readcr3( );

            for ( uintptr_t address = kernel_address; address <= kernel_address + size; address += 0x1000 )
            {
                const auto page_information = utils::get_page_information( ( void * )address, cr3 );

                page_information.PDE->Supervisor = 1;
                page_information.PDPTE->Supervisor = 1;
                page_information.PML4E->Supervisor = 1;

                if ( !page_information.PDE || ( page_information.PTE && !page_information.PTE->Present ) )
                {
                    
                }
                else
                {
                    page_information.PTE->Supervisor = 1;
                }
            }

            utils::swap_process( ( uintptr_t )o_process );
        }
        else
        {
            return false;
        }

        return true;
    }
}