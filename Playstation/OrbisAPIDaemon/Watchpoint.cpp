#include "stdafx.h"
#include "ProcessMonitor.h"
#include "Debug.h"
#include "Events.h"
#include "PtraceDefs.h"
#include "SignalDefs.h"
#include <KernelInterface.h>
#include <KernelExt.h>

void Debug::GetWatchpointList(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	auto CurrentWatchpoints = DebuggeeMonitor->Watchpoints;

	WatchpointListPacket packet;

	std::vector<WatchpointPacket> watchpoints(CurrentWatchpoints.size());

	for (int i = 0; i < CurrentWatchpoints.size(); i++)
	{
		watchpoints[i].set_index(CurrentWatchpoints[i]->Index);
		watchpoints[i].set_enabled(CurrentWatchpoints[i]->Enabled);
		watchpoints[i].set_address(CurrentWatchpoints[i]->Address);
		watchpoints[i].set_type(CurrentWatchpoints[i]->Type);
		watchpoints[i].set_length(CurrentWatchpoints[i]->Length);
	}

	*packet.mutable_watchpoints() = { watchpoints.begin(), watchpoints.end() };

	SendProtobufPacket(sock, packet);
}

void Debug::SetWatchpoint(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	int pid = CurrentPID;

	WatchpointPacket watchpoint;
	if (!RecieveProtoBuf(sock, &watchpoint))
	{
		Logger::Error("SetWatchpoint(): failed with recieve watchpoint data\n");
		SendStatePacket(sock, false, "Failed to recieve watchpoint data");
		return;
	}

	for (int i = 0; i < DebuggeeMonitor->Watchpoints.size(); i++)
	{
		Watchpoint* current = DebuggeeMonitor->Watchpoints[i].get();

		if (watchpoint.address() == current->Address)
		{
			Logger::Error("SetWatchpoint(): watchpoint is already set\n");
			SendStatePacket(sock, false, "Failed to set watchpoint (already set)");
			return;
		}

		if (watchpoint.index() == current->Index)
		{
			Logger::Error("SetWatchpoint(): watchpoint index is already occupied\n");
			SendStatePacket(sock, false, "Failed to set watchpoint (index is occupied)");
			return;
		}
	}

	Logger::Info("[add] Watchpoint:\n");
	Logger::Info("\tIndex: %i\n", watchpoint.index());
	Logger::Info("\tEnabled: %s\n", watchpoint.enabled() ? "True" : "False");
	Logger::Info("\tAddress: 0x%llX\n", watchpoint.address());
	Logger::Info("\tType: %i\n", watchpoint.type());
	Logger::Info("\tLength: %i\n", watchpoint.length());

	int rlwps = ptrace(PT_GETNUMLWPS, pid, nullptr, 0);
	if (rlwps == -1)
	{
		Logger::Error("SetWatchpoint(): ptrace(PT_GETNUMLWPS) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "GETNUMLWPS failed: %llX %s", __error(), strerror(errno));
		return;
	}

	std::unique_ptr<uint32_t[]> lwpids = std::make_unique<uint32_t[]>(rlwps);

	int res = ptrace(PT_GETLWPLIST, pid, lwpids.get(), rlwps);
	if (res == -1)
	{
		Logger::Error("SetWatchpoint(): ptrace(PT_GETLWPLIST) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "PT_GETLWPLIST failed: %llX %s", __error(), strerror(errno));
		return;
	}

	WatchpointData* watchData = &WatchData;
	memset(watchData, 0, sizeof(WatchpointData));

	watchData->dr[7] &= ~DR7_MASK(watchpoint.index());

	watchData->dr[watchpoint.index()] = watchpoint.address();
	watchData->dr[7] |= DR7_SET(watchpoint.index(), watchpoint.length(), watchpoint.type(), DR7_LOCAL_ENABLE | DR7_GLOBAL_ENABLE);

	for (int i = 0; i < rlwps; i++)
	{
		res = ptrace(PT_SETDBREGS, lwpids[i], watchData, 0);
		if (res == -1 && errno)
		{
			Logger::Error("SetWatchpoint(): [lwpid][%i] ptrace(PT_SETDBREGS) failed with error %llX %s\n", lwpids[i], __error(), strerror(errno));
			SendStatePacket(sock, false, "PT_SETDBREGS failed: %llX %s", __error(), strerror(errno));
			return;
		}
	}

	DebuggeeMonitor->Watchpoints.push_back(std::make_shared<Watchpoint>(watchpoint.index(), watchpoint.enabled(), watchpoint.address(), (WatchpointType)watchpoint.type(), (WatchpointLength)watchpoint.length()));

	Logger::Success("Watchpoint++ ref count: %i\n", DebuggeeMonitor->Watchpoints.size());

	SendStatePacket(sock, true, "");
}

void Debug::RemoveWatchpoint(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	int pid = CurrentPID;

	WatchpointPacket watchpoint;
	if (!RecieveProtoBuf(sock, &watchpoint))
	{
		Logger::Error("RemoveWatchpoint(): failed with recieve watchpoint data\n");
		SendStatePacket(sock, false, "Failed to recieve watchpoint data");
	}

	for (int i = 0; i < DebuggeeMonitor->Watchpoints.size(); i++)
	{
		auto current = DebuggeeMonitor->Watchpoints[i];

		if (watchpoint.index() == current->Index)
		{
			Logger::Info("[remove] Watchpoint:\n");
			Logger::Info("\tIndex: %i\n", current->Index);
			Logger::Info("\tEnabled: %s\n", current->Enabled ? "True" : "False");
			Logger::Info("\tAddress: 0x%llX\n", current->Address);
			Logger::Info("\tType: %i\n", current->Type);
			Logger::Info("\tLength: %i\n", current->Length);

			int rlwps = ptrace(PT_GETNUMLWPS, pid, nullptr, 0);
			if (rlwps == -1)
			{
				Logger::Error("SetWatchpoint(): ptrace(PT_GETNUMLWPS) failed with error %llX %s\n", __error(), strerror(errno));
				SendStatePacket(sock, false, "GETNUMLWPS failed: %llX %s", __error(), strerror(errno));
				return;
			}

			std::unique_ptr<uint32_t[]> lwpids = std::make_unique<uint32_t[]>(rlwps);

			int res = ptrace(PT_GETLWPLIST, pid, lwpids.get(), rlwps);
			if (res == -1)
			{
				Logger::Error("SetWatchpoint(): ptrace(PT_GETLWPLIST) failed with error %llX %s\n", __error(), strerror(errno));
				SendStatePacket(sock, false, "PT_GETLWPLIST failed: %llX %s", __error(), strerror(errno));
				return;
			}

			WatchpointData* watchData = &WatchData;

			watchData->dr[7] &= ~DR7_MASK(watchpoint.index());

			watchData->dr[watchpoint.index()] = 0;
			watchData->dr[7] |= DR7_SET(watchpoint.index(), 0, 0, DR7_DISABLE);

			for (int i = 0; i < rlwps; i++)
			{
				res = ptrace(PT_SETDBREGS, lwpids[i], watchData, 0);
				if (res == -1 && errno)
				{
					Logger::Error("RemoveWatchpoint(): [lwpid][%i] ptrace(PT_SETDBREGS) failed with error %llX %s\n", lwpids[i], __error(), strerror(errno));
					SendStatePacket(sock, false, "PT_SETDBREGS failed: %llX %s", __error(), strerror(errno));
					return;
				}
			}

			DebuggeeMonitor->Watchpoints.erase(DebuggeeMonitor->Watchpoints.begin() + i);
			Logger::Success("Watchpoint-- ref count: %i\n", DebuggeeMonitor->Watchpoints.size());
			SendStatePacket(sock, true, "");
			return;
		}
	}

	Logger::Error("RemoveBreakpoint(): No breakpoint matches the requested index\n");
	SendStatePacket(sock, false, "No breakpoint matches the requested index");
}