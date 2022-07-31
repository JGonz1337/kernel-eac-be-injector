#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include "interface/kinterface.h"
#include "utils/utils.h"
#include "map/mmap.h"
#include "xstr.h"

void main( )
{
	const auto pid = utils::PID( xstr("RainbowSix.exe") );

	if ( pid ) {
		kinterface->initialize( );
		mmap->map( pid, utils::read_file( xstr("image.dll") ).data( ) );
	}
	else {
		printf( xstr("game not found \n").c_str( ) );
	}

	kinterface->unload( );
}
