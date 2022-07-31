#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>

#include "imports.h"
#include "ia32.h"
#include "definitions.h"
#include "encrypt.h"
#include "crt.h"
#include "utils.h"
#include "interface.h"
#include "cache.h"
#include "cleaning.h"

__int64 __fastcall communication_handler( void *a1 )
{
	if ( !a1 || ExGetPreviousMode( ) != UserMode || reinterpret_cast< request_data * >( a1 )->unique != request_unique )
	{
		return cache::o_function_qword_2( a1 );
	}

	const auto request = reinterpret_cast< request_data * >( a1 );

	switch ( request->code )
	{
	case request_base:
	{
		base_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( base_request ) ) )
		{
			return 0;
		}

		if ( !data.name || !data.pid )
		{
			return 0;
		}

		const auto base = utils::get_module_handle( data.pid, data.name );

		if ( !base )
		{
			return 0;
		}

		reinterpret_cast< base_request * > ( request->data )->handle = base;

		return request_success;
	}
	case request_write:
	{
		write_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( write_request ) ) )
		{
			return 0;
		}

		if ( !data.address || !data.pid || !data.buffer || !data.size )
		{
			return 0;
		}

		PEPROCESS process;
		if ( PsLookupProcessByProcessId( ( HANDLE )data.pid, &process ) == STATUS_SUCCESS )
		{
			size_t bytes = 0;
			if ( MmCopyVirtualMemory( IoGetCurrentProcess( ), ( void * )reinterpret_cast< write_request * > ( request->data )->buffer, process, ( void * )data.address, data.size, KernelMode, &bytes ) != STATUS_SUCCESS || bytes != data.size )
			{
				ObDereferenceObject( process );
				return 0;
			}

			ObDereferenceObject( process );
		}
		else
		{
			return 0;
		}

		return request_success;
	}
	case request_read:
	{
		read_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( read_request ) ) )
		{
			return 0;
		}

		if ( !data.address || !data.pid || !data.buffer || !data.size )
		{
			return 0;
		}

		PEPROCESS process;
		if ( PsLookupProcessByProcessId( ( HANDLE )data.pid, &process ) == STATUS_SUCCESS )
		{
			size_t bytes = 0;
			if ( MmCopyVirtualMemory( process, ( void * )data.address, IoGetCurrentProcess( ), reinterpret_cast< write_request * > ( request->data )->buffer, data.size, KernelMode, &bytes ) != STATUS_SUCCESS || bytes != data.size )
			{
				ObDereferenceObject( process );
				return 0;
			}

			ObDereferenceObject( process );
		}
		else
		{
			return 0;
		}

		return request_success;
	} 
	case request_pattern:
	{
		pattern_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( pattern_request ) ) )
		{
			return 0;
		}

		PEPROCESS process;
		if ( PsLookupProcessByProcessId( ( HANDLE )data.pid, &process ) == STATUS_SUCCESS )
		{
			const auto o_process = utils::swap_process( ( uintptr_t )process );

			if ( !o_process )
			{
				utils::swap_process( ( uintptr_t )o_process );

				ObDereferenceObject( process );

				return 0;
			}

			const auto address = utils::find_pattern( data.base, data.signature );

			utils::swap_process( o_process );

			ObDereferenceObject( process );

			if ( !address )
			{
				return 0;
			}

			reinterpret_cast< pattern_request * > ( request->data )->address = address;
		}
		else
		{
			return 0;
		}

		return request_success;
	}
	case request_swap:
	{
		swap_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( allocate_request ) ) )
		{
			return 0;
		}

		if ( !data.src || !data.dst || !data.pid )
		{
			return 0;
		}

		PEPROCESS process;
		if ( PsLookupProcessByProcessId( ( HANDLE )data.pid, &process ) == STATUS_SUCCESS )
		{
			const auto o_process = utils::swap_process( ( uintptr_t )process );

			if ( !o_process )
			{
				utils::swap_process( ( uintptr_t )o_process );

				ObDereferenceObject( process );

				return 0;
			}

			uintptr_t old = 0;

			*( void ** )&old = InterlockedExchangePointer( ( void ** )data.src, ( void * )data.dst );

			utils::swap_process( ( uintptr_t )o_process );

			ObDereferenceObject( process );

			if ( !old )
			{
				return 0;
			}

			reinterpret_cast< swap_request * > ( request->data )->old = old;

			return request_success;
		}

		return 0;
	}
	case request_allocate:
	{
		allocate_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( allocate_request ) ) )
		{	
			return 0;
		}

		uintptr_t mdl = 0;
		const auto address = utils::allocate_kernel_memory( data.size, &mdl );

		if ( !address )
		{
			return 0;
		}

		if ( !mdl || !address )
		{
			return 0;
		}

		reinterpret_cast< allocate_request * >( request->data )->mdl = mdl;
		reinterpret_cast< allocate_request * >( request->data )->address = address;

		return request_success;
	}
	case request_free:
	{
		free_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( free_request ) ) )
		{
			return 0;
		}

		if ( !data.mdl || !data.address )
		{
			return 0;
		}

		MDL_INFORMATION mdl = { ( MDL * )data.mdl, ( uintptr_t )data.address };

		utils::free_mdl_memory( mdl );

		return request_success;
	}
	case request_expose:
	{
		expose_request data { 0 };

		if ( !utils::safe_copy( &data, request->data, sizeof( expose_request ) ) )
		{
			return 0;
		}

		if ( !data.pid || !data.address || !data.size )
		{
			return 0;
		}

		if ( !utils::expose_kernel_memory( data.pid, (uintptr_t)data.address, data.size ) )
		{
			return 0;
		}

		return request_success;
	}
	case request_unload:
	{
		*reinterpret_cast< unload_request * > ( request->data )->buffer = true;

		InterlockedExchangePointer( ( void ** )dereference( cache::qword_address ), ( void * )cache::o_qword_address );
		InterlockedExchangePointer( ( void ** )dereference( cache::function_qword_1 ), ( void * )cache::o_function_qword_1 );
		InterlockedExchangePointer( ( void ** )dereference( cache::function_qword_2 ), ( void * )cache::o_function_qword_2 );

		return request_success;
	}
	}

	return 0;
}

NTSTATUS DriverEntry( )
{
	const auto win32k = utils::get_kernel_module( e( "win32k.sys" ) );

	cache::qword_address = utils::find_pattern( win32k, e( "\x48\x8B\x05\x95\xCD\x05\x00" ), e( "xxxxxxx" ) );

	cache::function_qword_1 = utils::find_pattern( win32k, e( "\x48\x8B\x05\x11\xD7\x05\x00" ), e( "xxxxxxx" ) );

	cache::function_qword_2 = utils::find_pattern( win32k, e( "\x48\x8B\x05\xA1\xD6\x05\x00" ), e( "xxxxxxx" ) );

	*( void ** )&cache::o_qword_address = InterlockedExchangePointer( ( void ** )dereference( cache::qword_address ), ( void * )utils::find_pattern( win32k, e( "\x48\x83\xEC\x28\x48\x8B\x05\x11\xD7" ), e( "xxxxxxxxx" ) ) );

	*( void ** )&cache::o_function_qword_1 = InterlockedExchangePointer( ( void ** )dereference( cache::function_qword_1 ), ( void * )utils::find_pattern( win32k, e( "\x48\x83\xEC\x28\x48\x8B\x05\xA1\xD6" ), e( "xxxxxxxxx" ) ) );

	*( void ** )&cache::o_function_qword_2 = InterlockedExchangePointer( ( void ** )dereference( cache::function_qword_2 ), ( void * )communication_handler );

	return STATUS_SUCCESS;
}