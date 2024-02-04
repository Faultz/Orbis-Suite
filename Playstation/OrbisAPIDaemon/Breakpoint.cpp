#include "stdafx.h"
#include "ProcessMonitor.h"
#include "Debug.h"
#include "Events.h"
#include "PtraceDefs.h"
#include "SignalDefs.h"
#include <KernelInterface.h>
#include <KernelExt.h>

void Debug::GetBreakpointList(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	auto CurrentBreakpoint = DebuggeeMonitor->Breakpoints;

	BreakpointListPacket packet;

	std::vector<BreakpointPacket> breakpoints(CurrentBreakpoint.size());

	for (int i = 0; i < CurrentBreakpoint.size(); i++)
	{
		breakpoints[i].set_index(CurrentBreakpoint[i]->Index);
		breakpoints[i].set_enabled(CurrentBreakpoint[i]->Enabled);
		breakpoints[i].set_address(CurrentBreakpoint[i]->Address);
	}

	*packet.mutable_breakpoints() = { breakpoints.begin(), breakpoints.end() };

	SendProtobufPacket(sock, packet);
}

void Debug::SetBreakpoint(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	BreakpointPacket breakpoint;
	if (!RecieveProtoBuf(sock, &breakpoint))
	{
		Logger::Error("SetBreakpoint(): failed with recieve breakpoint data\n");
		SendStatePacket(sock, false, "Failed to recieve breakpoint data");
		return;
	}

	for (int i = 0; i < DebuggeeMonitor->Breakpoints.size(); i++)
	{
		auto current = DebuggeeMonitor->Breakpoints[i];

		if (breakpoint.address() == current->Address)
		{
			Logger::Error("SetBreakpoint(): breakpoint is already set\n");
			SendStatePacket(sock, false, "Failed to set breakpoint (already set)");
			return;
		}

		if (breakpoint.index() == current->Index)
		{
			Logger::Error("SetBreakpoint(): breakpoint index is already occupied\n");
			SendStatePacket(sock, false, "Failed to set breakpoint (index is occupied)");
			return;
		}
	}

	int Index = breakpoint.index();
	uint64_t Address = breakpoint.address();
	bool Enabled = breakpoint.enabled();

	uint8_t original;
	ReadWriteMemory(CurrentPID, reinterpret_cast<void*>(Address), &original, sizeof(uint8_t), false);

	uint8_t bp_inst = 0xCC;
	ReadWriteMemory(CurrentPID, reinterpret_cast<void*>(Address), &bp_inst, sizeof(uint8_t), true);

	Logger::Info("[add] Breakpoint:\n");
	Logger::Info("\tIndex: %i\n", breakpoint.index());
	Logger::Info("\tEnabled: %s\n", breakpoint.enabled() ? "True" : "False");
	Logger::Info("\tAddress: 0x%llX [%X]\n", breakpoint.address(), original);

	std::shared_ptr<Breakpoint> current = std::make_shared<Breakpoint>(Index, Enabled, Address, original);
	DebuggeeMonitor->Breakpoints.push_back(current);

	Logger::Success("Set breakpoint at 0x%016llX\n", Address);
	Logger::Success("Breakpoint++ ref count: %i\n", DebuggeeMonitor->Breakpoints.size());

	SendStatePacket(sock, true, "");
}

void Debug::RemoveBreakpoint(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	BreakpointPacket breakpoint;
	if (!RecieveProtoBuf(sock, &breakpoint))
	{
		Logger::Error("RemoveBreakpoint(): failed with recieve breakpoint data\n");
		SendStatePacket(sock, false, "Failed to recieve breakpoint data");
		return;
	}

	for (int i = 0; i < DebuggeeMonitor->Breakpoints.size(); i++)
	{
		auto current = DebuggeeMonitor->Breakpoints[i];
		if (current->IsSet(breakpoint))
		{
			Logger::Info("[remove] Breakpoint:\n");
			Logger::Info("\tIndex: %i\n", current->Index);
			Logger::Info("\tEnabled: %s\n", current->Enabled ? "True" : "False");
			Logger::Info("\tAddress: 0x%llX [%X]\n", current->Address, current->Original);

			ReadWriteMemory(CurrentPID, reinterpret_cast<void*>(current->Address), &current->Original, sizeof(uint8_t), true);

			Logger::Info("Removing breakpoint at 0x%016llX\n", current->Address);

			DebuggeeMonitor->Breakpoints.erase(DebuggeeMonitor->Breakpoints.begin() + i);
			Logger::Success("Breakpoint-- ref count: %i\n", DebuggeeMonitor->Breakpoints.size());
			SendStatePacket(sock, true, "");
			return;
		}
	}

	Logger::Error("RemoveBreakpoint(): No breakpoint matches the requested index\n");
	SendStatePacket(sock, false, "No breakpoint matches the requested index");
}
