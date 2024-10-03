#pragma D option quiet

/* For widestring print, from "newprocesstracker.d" example */
struct ustr{uint16_t buffer[256];};

syscall::NtAlpcSendWaitReceivePort:entry
{
/*++
__in HANDLE PortHandle,                                                    arg0
__in ULONG Flags,                                                          arg1
__in_bcount_opt(SendMessage->u1.s1.TotalLength) PPORT_MESSAGE SendMessage, arg2
__inout_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,                arg3
__out_bcount_opt(*BufferLength,*BufferLength) PPORT_MESSAGE ReceiveMessage,arg4
__inout_opt PSIZE_T BufferLength,                                          arg5
__inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,             arg6
__in_opt PLARGE_INTEGER Timeout                                            arg7
--*/

	/* Resolve process */
	this->curproc = (nt`_EPROCESS*)(((nt`_KTHREAD*) curthread)->Process);
	this->processid = (string)this->curproc->ImageFileName;
	printf("\nProcess %s, EPROCESS: %p, HANDLE: %llx\n", this->processid, this->curproc, arg0);
	
	/* Resolve handle:
	- EPROCESS.ObjectTable.TableCode is used
	- from nt!ExpLookupHandleTableEntry reversing:
		if TableCode last bits are set, several "tables" are involved (as pages in pagination)
	*/
	this->handle_table = (unsigned long long)(this->curproc->ObjectTable->TableCode);
	this->table_code_switch = this->handle_table & 3;
	this->handle_value = arg0 & 0xFFFFFFFFFFFFFFFC;
	
	/* One page indirection */
	if (this->table_code_switch == 1)
	{
		this->handle_table = *(unsigned long long*)(this->handle_table + (8 * (this->handle_value >> 10)) - 1);
		this->handle_value &= 0x3FF;
	}
	/* Two pages indirection */
	else if (this->table_code_switch == 2)
	{
		this->handle_table = *(unsigned long long*)(this->handle_table + (8 * (this->handle_value >> 19)) - 2);
		this->handle_table = *(unsigned long long*)(this->handle_table + (8 * ((this->handle_value >> 10) & 0x1FF)));
		this->handle_value &= 0x3FF;
	}
    this->handle_entry = (nt`_HANDLE_TABLE_ENTRY*)(this->handle_table + 4 * this->handle_value);
	this->object_ptr = (nt`_OBJECT_HEADER*)(((unsigned long long)this->handle_entry->ObjectPointerBits) << 4 | 0xFFFF000000000000 );
		
	/* Resolve communication port */
	this->alpc_obj = (nt`_ALPC_PORT*) ((unsigned long long)this->object_ptr + offsetof (nt`_OBJECT_HEADER, Body));
	this->conn_port = this->alpc_obj->CommunicationInfo->ConnectionPort;
	
	/* Resolve name */
	this->conn_port_obj_hdr = (nt`_OBJECT_HEADER*)((unsigned long long) this->conn_port - offsetof (nt`_OBJECT_HEADER, Body));
	if (this->conn_port_obj_hdr->InfoMask & 3 < 2) {
		/* nt!_OBJECT_HEADER_NAME_INFO is not set */
		printf("UNKNOWN_PORT_NAME");
    }
	else {
		this->header_name = (nt`_OBJECT_HEADER_NAME_INFO*)((unsigned long long) this->conn_port_obj_hdr - 0x20);
		printf("[ALPC Port] %*ws", this->header_name->Name.Length / 2, ((struct ustr*)this->header_name->Name.Buffer)->buffer);
	}
	
	/* Resolve client / server */
	this->owner = this->conn_port->OwnerProcess;
	printf("\nOwner: %s (%d)\n", (string)this->owner->ImageFileName, (unsigned long long)this->owner->UniqueProcessId);
	this->client_port = this->alpc_obj->CommunicationInfo->ClientCommunicationPort;
	if (this->client_port == 0) {
		printf("No client\n");
	} else {
		printf("Client: %s (%d)\n", (string)this->client_port->OwnerProcess->ImageFileName, (unsigned long long)this->client_port->OwnerProcess->UniqueProcessId);
	}
	
	/* ustack(); */
}
