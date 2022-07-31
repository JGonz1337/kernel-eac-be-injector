namespace clean
{
	bool null_pfn( PMDL mdl )
	{
		PPFN_NUMBER mdl_pages = MmGetMdlPfnArray( mdl );
		if ( !mdl_pages ) { return false; }

		ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES( MmGetMdlVirtualAddress( mdl ), MmGetMdlByteCount( mdl ) );

		ULONG null_pfn = 0x0;

		MM_COPY_ADDRESS source_address = { 0 };
		source_address.VirtualAddress = &null_pfn;

		for ( ULONG i = 0; i < mdl_page_count; i++ )
		{
			size_t bytes = 0;
			MmCopyMemory( &mdl_pages[i], source_address, sizeof( ULONG ), MM_COPY_MEMORY_VIRTUAL, &bytes );
		}

		return true;
	}
}