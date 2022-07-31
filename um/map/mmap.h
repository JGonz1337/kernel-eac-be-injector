class mmap_t
{
private:

	unsigned char remote_call_dll_main[103] = {
		0x48, 0x83, 0xEC, 0x38,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x39, 0xFF, 0x90, 0x39, 0xC0,
		0x90,
		0x48, 0x89, 0x44, 0x24, 0x20,
		0x48, 0x8B, 0x44, 0x24,
		0x20, 0x83, 0x38, 0x00, 0x75, 0x39,
		0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x44, 0x24, 0x20,
		0x48, 0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20,
		0x48, 0x8B,
		0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x81, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0x48,
		0x39, 0xC0, 0x90, 0xCC
	};

	typedef struct _remote_dll {
		INT status;
		uintptr_t dll_main_address;
		HINSTANCE dll_base;
	} remote_dll, *premote_dll;

	auto get_nt_headers( const std::uintptr_t image_base ) -> IMAGE_NT_HEADERS *
	{
		const auto dos_header = reinterpret_cast< IMAGE_DOS_HEADER * > ( image_base );

		return reinterpret_cast< IMAGE_NT_HEADERS * > ( image_base + dos_header->e_lfanew );
	}

	auto rva_va( const std::uintptr_t rva, IMAGE_NT_HEADERS *nt_header, void *local_image ) -> void *
	{
		const auto first_section = IMAGE_FIRST_SECTION( nt_header );

		for ( auto section = first_section; section < first_section + nt_header->FileHeader.NumberOfSections; section++ )
		{
			if ( rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize )
			{
				return ( unsigned char * )local_image + section->PointerToRawData + ( rva - section->VirtualAddress );
			}
		}

		return 0;
	}

	auto relocate_image( void *remote_image, void *local_image, IMAGE_NT_HEADERS *nt_header ) -> bool
	{
		typedef struct _RELOC_ENTRY
		{
			ULONG ToRVA;
			ULONG Size;
			struct
			{
				WORD Offset : 12;
				WORD Type : 4;
			} Item[1];
		} RELOC_ENTRY, *PRELOC_ENTRY;

		const auto delta_offset = ( std::uintptr_t )remote_image - nt_header->OptionalHeader.ImageBase;

		if ( !delta_offset )
		{
			return true;
		}

		else if ( !( nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ) )
		{
			return false;
		}

		auto relocation_entry = ( RELOC_ENTRY * )rva_va( nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_header, local_image );
		const auto relocation_end = ( std::uintptr_t )relocation_entry + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if ( relocation_entry == nullptr )
		{
			return true;
		}

		while ( ( std::uintptr_t )relocation_entry < relocation_end && relocation_entry->Size )
		{
			auto records_count = ( relocation_entry->Size - 8 ) >> 1;

			for ( auto i = 0ul; i < records_count; i++ )
			{
				WORD fixed_type = ( relocation_entry->Item[i].Type );
				WORD shift_delta = ( relocation_entry->Item[i].Offset ) % 4096;

				if ( fixed_type == IMAGE_REL_BASED_ABSOLUTE )
				{
					continue;
				}

				if ( fixed_type == IMAGE_REL_BASED_HIGHLOW || fixed_type == IMAGE_REL_BASED_DIR64 )
				{
					auto fixed_va = ( std::uintptr_t )rva_va( relocation_entry->ToRVA, nt_header, local_image );

					if ( !fixed_va )
					{
						fixed_va = ( std::uintptr_t )local_image;
					}

					*( std::uintptr_t * )( fixed_va + shift_delta ) += delta_offset;
				}
			}

			relocation_entry = ( PRELOC_ENTRY )( ( LPBYTE )relocation_entry + relocation_entry->Size );
		}

		return true;
	}

	auto resolve_function_address( LPCSTR module_name, LPCSTR function_name ) -> std::uintptr_t
	{
		const auto handle = LoadLibraryExA( module_name, nullptr, DONT_RESOLVE_DLL_REFERENCES );

		const auto offset = ( std::uintptr_t )GetProcAddress( handle, function_name ) - ( std::uintptr_t )handle;

		FreeLibrary( handle );

		return offset;
	}

	auto write_sections( int pid, void *module_base, void *local_image, IMAGE_NT_HEADERS *nt_header ) -> void
	{
		auto section = IMAGE_FIRST_SECTION( nt_header );

		for ( WORD count = 0; count < nt_header->FileHeader.NumberOfSections; count++, section++ )
		{
			kinterface->write_virtual_memory( pid, ( std::uintptr_t )( ( std::uintptr_t )module_base + section->VirtualAddress ), ( void * )( ( std::uintptr_t )local_image + section->PointerToRawData ), section->SizeOfRawData );
		}
	}

	auto resolve_import( void *local_image, IMAGE_NT_HEADERS *nt_header ) -> bool
	{
		IMAGE_IMPORT_DESCRIPTOR *import_description = ( IMAGE_IMPORT_DESCRIPTOR * )rva_va( nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_header, local_image );

		if ( !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size )
		{
			return true;
		}

		LPSTR module_name = NULL;

		while ( ( module_name = ( LPSTR )rva_va( import_description->Name, nt_header, local_image ) ) )
		{
			const auto base_image = ( std::uintptr_t )LoadLibraryA( module_name );

			if ( !base_image )
			{
				return false;
			}

			auto import_header_data = ( IMAGE_THUNK_DATA * )rva_va( import_description->FirstThunk, nt_header, local_image );

			while ( import_header_data->u1.AddressOfData )
			{
				if ( import_header_data->u1.Ordinal & IMAGE_ORDINAL_FLAG )
				{
					import_header_data->u1.Function = base_image + resolve_function_address( module_name, ( LPCSTR )( import_header_data->u1.Ordinal & 0xFFFF ) );
				}
				else
				{
					IMAGE_IMPORT_BY_NAME *ibn = ( IMAGE_IMPORT_BY_NAME * )rva_va( import_header_data->u1.AddressOfData, nt_header, local_image );
					import_header_data->u1.Function = base_image + resolve_function_address( module_name, ( LPCSTR )ibn->Name );
				}
				import_header_data++;
			}
			import_description++;
		}

		return true;
	}

	auto erase_discardable_section( int pid, void *module_base, IMAGE_NT_HEADERS *nt_header ) -> void
	{
		auto section = IMAGE_FIRST_SECTION( nt_header );

		for ( WORD count = 0; count < nt_header->FileHeader.NumberOfSections; count++, section++ )
		{
			if ( section->SizeOfRawData == 0 )
			{
				continue;
			}

			if ( section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE )
			{
				auto zero_memory = VirtualAlloc( 0, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

				kinterface->write_virtual_memory( pid, ( std::uintptr_t )( ( std::uintptr_t )module_base + section->VirtualAddress ), zero_memory, section->SizeOfRawData );

				VirtualFree( zero_memory, 0, MEM_RELEASE );
			}
		}
	}

	auto vmt_hook( const int pid, void *base, IMAGE_NT_HEADERS *nt_header ) -> bool
	{
		const auto shellcode_size = sizeof( remote_call_dll_main ) + sizeof( remote_dll );

		std::uintptr_t mdl = 0;
		const auto shellcode_allocation = kinterface->allocate_kernel_memory( nt_header->OptionalHeader.SizeOfImage, &mdl );

		if ( !kinterface->expose_kernel_memory( GetCurrentProcessId( ), shellcode_allocation, nt_header->OptionalHeader.SizeOfImage ) )
		{
			return false;
		}

		if ( !kinterface->expose_kernel_memory( pid, shellcode_allocation, nt_header->OptionalHeader.SizeOfImage ) ) 
		{
			return false;
		}

		printf( "exposed kernel memory [shellcode_allocation]: 0x%llx\n", shellcode_allocation );

		const auto local_allocation = VirtualAlloc( 0, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

		memcpy( local_allocation, &remote_call_dll_main, sizeof( remote_call_dll_main ) );

		const auto shellcode_data = ( std::uintptr_t )shellcode_allocation + sizeof( remote_call_dll_main );

		memcpy( ( void * )( ( std::uintptr_t )local_allocation + 0x6 ), &shellcode_data, sizeof( std::uintptr_t ) );

		auto remote = ( remote_dll * )( ( std::uintptr_t )local_allocation + sizeof( remote_call_dll_main ) );

		remote->dll_base = ( HINSTANCE )base;

		remote->dll_main_address = ( ( std::uintptr_t )base + nt_header->OptionalHeader.AddressOfEntryPoint );

		if ( !kinterface->write_virtual_memory( pid, ( std::uintptr_t )shellcode_allocation, local_allocation, shellcode_size ) )
		{
			return false;
		}

		const auto renderer = kinterface->get_module_base( pid, "DiscordHook64.dll" );
		
		/* MEDAL.TV
		
		if ( !renderer )
		{
			printf( "renderer not found\n" );
			return false;
		}

		auto present_ptr = kinterface->find_signature( pid, renderer, "FF 15 ?? ?? ?? ?? 48 8B 03 48 8B CB FF 50 ?? 8B C6" );

		if ( !present_ptr )
		{
			printf( "present ptr not found\n" );
			return false;
		}

		printf( "present_ptr: 0x%llx\n", present_ptr );

		const auto present_address = present_ptr + kinterface->read_virtual_memory<uint32_t> ( pid, present_ptr + 2 ) + 6;

		printf( "present_address: 0x%llx\n", present_address );

		*/

		const auto present_address = renderer + 0x1B3080;

		const auto old_ptr = kinterface->swap_virtual_pointer( pid, present_address, ( std::uintptr_t )shellcode_allocation );

		if ( !old_ptr )
		{
			return false;
		}

		while ( remote->status != 0x81 )
		{
			kinterface->read_virtual_memory( pid, ( std::uintptr_t )shellcode_data, remote, sizeof( remote_dll ) );
		}

		if ( !kinterface->swap_virtual_pointer( pid, present_address, old_ptr ) )
		{
			return false;
		}

		printf( "successfully executed\n" );

		BYTE null_shellcode[shellcode_size] = { 0 };

		if ( !kinterface->write_virtual_memory( pid, ( std::uintptr_t )shellcode_allocation, null_shellcode, shellcode_size ) ) 
		{
			return false;
		}

		if ( !kinterface->free_virtual_memory( shellcode_allocation, mdl ) )
		{
			return false;
		}

		VirtualFree( local_allocation, 0, MEM_RELEASE );

		return true;
	}

public:

	auto map( const int pid, void *buffer ) -> bool
	{
		const auto nt_header = get_nt_headers( reinterpret_cast< std::uintptr_t > ( buffer ) );
		printf( "nt_headers: 0x%llx\n", nt_header );

		std::uintptr_t mdl = 0;
		const auto base = kinterface->allocate_kernel_memory( nt_header->OptionalHeader.SizeOfImage, &mdl );
		
		if ( !base )
		{
			printf( "invalid base.\n" );
			return false;
		}

		if ( !kinterface->expose_kernel_memory( GetCurrentProcessId( ), base, nt_header->OptionalHeader.SizeOfImage ))
		{
			printf( "invalid expose 0.\n" );
			return false;
		}

		if ( !kinterface->expose_kernel_memory( pid, base, nt_header->OptionalHeader.SizeOfImage ) )
		{
			printf( "invalid expose 1.\n" );
			return false;
		}

		printf( "exposed kernel memory [base]: 0x%llx\n", base );

		if ( !relocate_image( base, buffer, nt_header ) ) 
		{
			return false;
		}
		printf( "relocated image\n" );

		if ( !resolve_import( buffer, nt_header ) ) 
		{
			return false;
		}
		printf( "resolved imports\n" );

		write_sections( pid, base, buffer, nt_header );
		printf( "wrote sections\n" );

		if ( !vmt_hook( pid, base, nt_header ) )
		{
			return false;
		}

		printf( "shellcode called\n" );

		erase_discardable_section( pid, base, nt_header );
		printf( "erased discardable section\n" );

		VirtualFree( buffer, 0, MEM_RELEASE );
		printf( "cleaning up\n" );

		return true;
	}
};

static mmap_t *mmap = new mmap_t( );