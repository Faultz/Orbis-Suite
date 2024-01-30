#include "stdafx.h"
#include "Library.h"
#include "Debug.h"
#include <KernelInterface.h>
#include <GoldHEN.h>
#include <PtraceDefs.h>

void Library::LoadLibrary(SceNetId s)
{
	if (!Debug::CheckDebug(s))
		return;

	SPRXPacket packet;
	RecieveProtoBuf(s, &packet);

	// Get Process name.
	char processName[32];
	sceKernelGetProcessName(Debug::CurrentPID, processName);

	// Load the library.
	auto handle = sys_sdk_proc_prx_load(processName, (char*)packet.path().c_str());

	// Once I can migrate from hen I can error handle here better.
	if (handle <= 0)
	{
		SendStatePacket(s, false, "Failed to load the SPRX %s.", packet.path().c_str());
		return;
	}
	else
		SendStatePacket(s, true, "");

	// Send the result.
	Sockets::SendInt(s, handle);
}

void Library::UnloadLibrary(SceNetId s)
{
	if (!Debug::CheckDebug(s))
		return;

	SPRXPacket packet;
	RecieveProtoBuf(s, &packet);

	// Get Process name.
	char processName[32];
	sceKernelGetProcessName(Debug::CurrentPID, processName);

	// Unload the library.
	auto result = sys_sdk_proc_prx_unload(processName, packet.handle());

	// Once I can migrate from hen I can error handle here better.
	if (result != 0)
	{
		SendStatePacket(s, false, "Failed to unload the SPRX %s.", packet.path().c_str());
		return;
	}
	else
		SendStatePacket(s, true, "");
}

void Library::ReloadLibrary(SceNetId s)
{
	if (!Debug::CheckDebug(s))
		return;

	SPRXPacket packet;
	RecieveProtoBuf(s, &packet);

	// Get Process name.
	char processName[32];
	sceKernelGetProcessName(Debug::CurrentPID, processName);

	// Unload the library.
	auto result = sys_sdk_proc_prx_unload(processName, packet.handle());
	if (result != 0)
	{
		Logger::Error("Failed to unload %d\n", packet.handle());

		Sockets::SendInt(s, result);

		return;
	}

	// Load the library.
	auto handle = sys_sdk_proc_prx_load(processName, (char*)packet.path().c_str());

	// Once I can migrate from hen I can error handle here better.
	if (handle <= 0)
	{
		SendStatePacket(s, false, "Failed to reload the SPRX %s.", packet.path().c_str());
		return;
	}
	else
	{
		// Send the results.
		SendStatePacket(s, true, "");
		Sockets::SendInt(s, handle);
	}
}

void Library::GetLibraryList(SceNetId s)
{
	LibraryListPacket packet;

	if (!Debug::CheckDebug(s))
		return;

	auto libraries = std::make_unique<OrbisLibraryInfo[]>(256);
	int actualCount = GetLibraries(Debug::CurrentPID, libraries.get(), 256);

	// Populate the vector list.
	std::vector<LibraryInfoPacket> vectorList;
	for (int i = 0; i < actualCount; i++)
	{
		LibraryInfoPacket infoPacket;
		infoPacket.set_handle(libraries[i].Handle);
		infoPacket.set_path(libraries[i].Path);
		infoPacket.set_mapbase(libraries[i].MapBase);
		infoPacket.set_mapsize(libraries[i].MapSize);
		infoPacket.set_textsize(libraries[i].TextSize);
		infoPacket.set_database(libraries[i].DataBase);
		infoPacket.set_datasize(libraries[i].DataSize);

		vectorList.push_back(infoPacket);
	}

	// Set the parsed list into the protobuf packet.
	*packet.mutable_libraries() = { vectorList.begin(), vectorList.end() };

	// Send the list to host.
	SendProtobufPacket(s, packet);
}

#pragma pack(push, 4)
struct ptrace_vm_entry {
	int		pve_entry;	/* Entry number used for iteration. */
	int		pve_timestamp;	/* Generation number of VM map. */
	unsigned long long		pve_start;	/* Start VA of range. */
	unsigned long long		pve_end;	/* End VA of range (incl). */
	unsigned long long		pve_offset;	/* Offset in backing object. */
	int		pve_prot;	/* Protection of memory range. */
	size_t		pve_pathlen;	/* Size of path. */
	int			pve_fileid;	/* File ID. */
	uint32_t	pve_fsid;	/* File system ID. */
	char _unk[0x4];
	char* pve_path;	/* Path name of object. */
};
#pragma pack(pop)

//#undef offsetof
//#define offsetof(T, member) ((size_t)__INTADDR__(&(((T *)0)->member)))
//char off[offsetof(ptrace_vm_entry, pve_path)];

void Library::GetPageList(SceNetId s)
{
	PagesListPacket packet;

	if (!Debug::CheckDebug(s))
		return;

	//std::unique_ptr<ptrace_vm_entry[]> pages = std::make_unique<ptrace_vm_entry[]>(1000);

	//char buffer[0x5000];
	//int count = 0;
	//ptrace_vm_entry entry;
	//memset(&entry, 0, sizeof(ptrace_vm_entry));
	//entry.pve_entry = 0;

	//std::vector<ptrace_vm_entry> pages;

	//while (ptrace(PT_VM_ENTRY, Debug::CurrentPID, &entry, 0) == 0)
	//{
	//	entry.pve_path = buffer;
	//	entry.pve_pathlen = sizeof(buffer);

	//	if (pages.size() < 10)
	//	{
	//		printf("page %i: %s\n", pages.size(), entry.pve_path);

	//		hexdump(&entry, 0x100);
	//	}

	//	pages.push_back(entry);
	//}

	auto pages = std::make_unique<OrbisProcessPage[]>(1000);
	int actualCount = GetPages(Debug::CurrentPID, pages.get(), 1000);

	// Populate the vector list.
	std::vector<PagePacket> vectorList;
	for (int i = 0; i < actualCount; i++)
	{
		PagePacket infoPacket;
		infoPacket.set_name(pages[i].Name);
		infoPacket.set_start(pages[i].Start);
		infoPacket.set_end(pages[i].End);
		infoPacket.set_offset(pages[i].Offset);
		infoPacket.set_size(pages[i].Size);
		infoPacket.set_prot(pages[i].Prot);

		vectorList.push_back(infoPacket);
	}

	// Set the parsed list into the protobuf packet.
	*packet.mutable_pages() = { vectorList.begin(), vectorList.end() };

	// Send the list to host.
	SendProtobufPacket(s, packet);
}

void Library::GetNamedObjectList(SceNetId s)
{
	NamedObjectListPacket packet;

	if (!Debug::CheckDebug(s))
		return;

	auto objects = std::make_unique<OrbisNamedObject[]>(1000);
	int actualCount = GetNamedObjects(Debug::CurrentPID, objects.get(), 1000);

	// Populate the vector list.
	std::vector<NamedObjectPacket> vectorList;
	for (int i = 0; i < actualCount; i++)
	{
		NamedObjectPacket infoPacket;
		infoPacket.set_name(objects[i].Name);

		vectorList.push_back(infoPacket);
	}

	// Set the parsed list into the protobuf packet.
	*packet.mutable_objects() = { vectorList.begin(), vectorList.end() };

	// Send the list to host.
	SendProtobufPacket(s, packet);
}