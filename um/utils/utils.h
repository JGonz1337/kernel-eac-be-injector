namespace utils
{
	auto PID( std::string name ) -> int
	{
		const auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

		PROCESSENTRY32 entry { };
		entry.dwSize = sizeof( PROCESSENTRY32 );

		Process32First( snapshot, &entry );
		do
		{
			if ( !name.compare ( entry.szExeFile ) )
			{
				return entry.th32ProcessID;
			}

		} while ( Process32Next( snapshot, &entry ) );
	}

	auto read_file( const std::string filename ) -> std::vector<uint8_t>
	{
		std::ifstream stream( filename, std::ios::binary );

		std::vector<uint8_t> buffer { };

		buffer.assign( ( std::istreambuf_iterator<char>( stream ) ), std::istreambuf_iterator<char>( ) );
		
		stream.close( );

		return buffer;
	}
}