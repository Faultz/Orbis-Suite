#include "stdafx.h"
#include "ProcessMonitor.h"
#include "Debug.h"
#include "Events.h"
#include "PtraceDefs.h"
#include "SignalDefs.h"
#include <KernelInterface.h>
#include <KernelExt.h>

WatchpointData WatchData;

std::mutex Debug::DebugMtx;
bool Debug::IsDebugging;
int Debug::CurrentPID;
std::shared_ptr<ProcessMonitor> Debug::DebuggeeMonitor;

bool Debug::CheckDebug(SceNetId s)
{
	if (!IsDebugging || CurrentPID == -1)
	{
		Sockets::SendInt(s, 0);
		return false;
	}

	Sockets::SendInt(s, 1);
	return true;
}

void Debug::Attach(SceNetId sock)
{
	auto pid = 0;
	if (!Sockets::RecvInt(sock, &pid))
	{
		Logger::Error("Attach(): Failed to recieve the pid\n");
		SendStatePacket(sock, false, "Failed to recieve the pid.");
		return;
	}

	// Get Process name.
	char processName[32];
	sceKernelGetProcessName(pid, processName);

	{
		std::unique_lock<std::mutex> lock(DebugMtx);

		Logger::Info("Attach(): Attempting to attach to %s (%d)\n", processName, pid);

		// If we are currently debugging another process lets detach from it.
		if (!TryDetach(pid))
		{
			Logger::Error("Attach(): TryDetach Failed. :(\n");
			SendStatePacket(sock, false, "Try detach failed.");
			return;
		}
		
		// Use ptrace to attach to begin debugging this pid.
		int res = ptrace(PT_ATTACH, pid, nullptr, 0);
		if (res != 0)
		{
			Logger::Error("Attach(): ptrace(PT_ATTACH) failed with error %llX %s\n", __error(), strerror(errno));
			SendStatePacket(sock, false, "Attach failed: %llX %s", __error(), strerror(errno));
			return;
		}
		
		// Wait till the process haults.
		waitpid(pid, NULL, 0);
		
		// Attaching by default will stop execution of the remote process. Lets continue it now.
		res = ptrace(PT_CONTINUE, pid, (void*)1, 0);
		if (res != 0)
		{
			Logger::Error("Attach(): ptrace(PT_CONTINUE) failed with error %llX %s\n", __error(), strerror(errno));
			SendStatePacket(sock, false, "Continue failed: %llX %s", __error(), strerror(errno));
			return;
		}

		// Set current debugging state.
		IsDebugging = true;
		CurrentPID = pid;

		// Set up proc monitor.
		DebuggeeMonitor = std::make_shared<ProcessMonitor>(pid);
		DebuggeeMonitor->OnExit = OnExit; // Fired when a process dies.
		DebuggeeMonitor->OnException = OnException; // Fired when the process being debugged encounters an excepton.
	}

	// Send attach event to host.
	Events::SendEvent(Events::EVENT_ATTACH, pid);

	Logger::Info("Attach(): Attached to %s(%d)\n", processName, pid);

	// Send the happy state.
	SendStatePacket(sock, true, "");

	// Mount /data/ in sandbox.
	if (strcmp(processName, "SceShellCore"))
	{
		// Get app info.
		SceAppInfo appInfo;
		sceKernelGetAppInfo(pid, &appInfo);

		// Mount data & system into sandbox
		LinkDir("/data/", va("/mnt/sandbox/%s_000/data", appInfo.TitleId).c_str());
		LinkDir("/system/", va("/mnt/sandbox/%s_000/system", appInfo.TitleId).c_str());
	}
}

void Debug::Detach(SceNetId sock)
{
	if (!IsDebugging)
		Sockets::SendInt(sock, 0);

	{
		std::unique_lock<std::mutex> lock(DebugMtx);

		// Get app info.
		SceAppInfo appInfo;
		sceKernelGetAppInfo(CurrentPID, &appInfo);

		// Unmount the linked dirs.
		unmount(va("/mnt/sandbox/%s_000/data", appInfo.TitleId).c_str(), MNT_FORCE);
		unmount(va("/mnt/sandbox/%s_000/system", appInfo.TitleId).c_str(), MNT_FORCE);

		if (TryDetach(CurrentPID))
		{
			// Reset vars.
			IsDebugging = false;
			CurrentPID = -1;

			Events::SendEvent(Events::EVENT_DETACH);
			SendStatePacket(sock, true, "");
		}
		else
		{
			Logger::Error("Failed to detach from %d\n", CurrentPID);
			SendStatePacket(sock, false, "Failed to detach from %d", CurrentPID);
		}
	}
}

void Debug::Current(SceNetId sock)
{
	if (!IsDebugging)
	{
		Sockets::SendInt(sock, -1);
	}
	else
	{
		Sockets::SendInt(sock, CurrentPID);
	}
}

void Debug::RWMemory(SceNetId s, bool write)
{
	if (!CheckDebug(s))
		return;

	RWPacket packet;
	if (!RecieveProtoBuf<RWPacket>(s, &packet))
	{
		SendStatePacket(s, false, "Failed to parse the next protobuf packet.");
		return;
	}

	// Allocate space for our read / write.
	std::unique_ptr<unsigned char[]> buffer;
	try
	{
		
		buffer = std::make_unique<unsigned char[]>(packet.length());
	}
	catch (const std::exception& ex)
	{
		SendStatePacket(s, false, "Failed to allocate enough memory.");
		return;
	}

	// TODO: Might be a good idea to make sure we are landing in the right memory regions. Should be good to check the vmmap and the library list.
	//		 Pretty sure we can use the syscall from the kernel context and specify the debug proc to achieve the same. 
	//		 (syscall 572) sceKernelVirtualQuery(const void* address, int flags, SceKernelVirtualQueryInfo* info, size_t infoSize)

	if (write)
	{
		// Send happy packet so we can continue on.
		SendStatePacket(s, true, "");

		// Recieve the data we are going to write.
		if (!Sockets::RecvLargeData(s, buffer.get(), packet.length()))
		{
			Logger::Error("Debug::RWMemory(): Failed to recieve memory to write\n");
			SendStatePacket(s, false, " Failed to recieve memory to write.");
			return;
		}

		// Write the memory we recieved using the kernel.
		if (!ReadWriteMemory(CurrentPID, (void*)packet.address(), (void*)buffer.get(), packet.length(), true))
		{
			Logger::Error("Debug::RWMemory(): Failed to write memory to process %i at %llX\n", CurrentPID, packet.address());
			SendStatePacket(s, false, "Failed to write memory to process %i at %llX.", CurrentPID, packet.address());
			return;
		}

		// Send happy packet
		SendStatePacket(s, true, "");
	}
	else
	{
		// Read the memory requested using the kernel.
		if (!ReadWriteMemory(CurrentPID, (void*)packet.address(), (void*)buffer.get(), packet.length(), false))
		{
			Logger::Error("Debug::RWMemory(): Failed to read memory to process %i at %llX\n", CurrentPID, packet.address());
			SendStatePacket(s, false, "Failed to read memory to process %i at %llX.", CurrentPID, packet.address());
			return;
		}

		// Send happy packet
		SendStatePacket(s, true, "");

		// Send the data we read.
		if (!Sockets::SendLargeData(s, buffer.get(), packet.length()))
		{
			Logger::Error("Failed to send memory\n");
			return;
		}
	}
}

void Debug::OnExit()
{
	Logger::Info("Process %d has died!\n", CurrentPID);

	// Send the event to the host that the process has died.
	Events::SendEvent(Events::EVENT_DIE, CurrentPID);

	// Get app info.
	SceAppInfo appInfo;
	sceKernelGetAppInfo(CurrentPID, &appInfo);

	// Unmount the linked dirs.
	unmount(va("/mnt/sandbox/%s_000/data", appInfo.TitleId).c_str(), MNT_FORCE);
	unmount(va("/mnt/sandbox/%s_000/system", appInfo.TitleId).c_str(), MNT_FORCE);

	// For now just detach.
	if (!TryDetach(CurrentPID))
	{
		Logger::Error("OnExit(): TryDetach Failed. :(\n");
		return;
	}

	Events::SendEvent(Events::EVENT_DETACH);
}

void Debug::OnException(int status)
{
	int signal = WSTOPSIG(status);

	switch (signal)
	{
	case SIGSTOP:
		Logger::Info("SIGSTOP\n");
		break;
	}

	// Get app info.
	SceAppInfo appInfo;
	sceKernelGetAppInfo(CurrentPID, &appInfo);

	// Unmount the linked dirs.
	unmount(va("/mnt/sandbox/%s_000/data", appInfo.TitleId).c_str(), MNT_FORCE);
	unmount(va("/mnt/sandbox/%s_000/system", appInfo.TitleId).c_str(), MNT_FORCE);

	// For now just detach.
	if (!TryDetach(CurrentPID))
	{
		Logger::Error("OnException(): TryDetach Failed. :(\n");
		return;
	}

	Events::SendEvent(Events::EVENT_DETACH);
}

bool Debug::TryDetach(int pid)
{
	// Check if we are even attached.
	if (!IsDebugging)
	{
		return true;
	}

	// Detach from the process.
	int res = ptrace(PT_DETACH, pid, nullptr, 0);
	if (res != 0)
	{
		// Check if proc is dead anyway and just detach.
		std::vector<kinfo_proc> procList;
		GetProcessList(procList);

		if (std::find_if(procList.begin(), procList.end(), [=](const kinfo_proc& arg) { return arg.pid == pid; }) == procList.end())
		{
			// Reset vars.
			IsDebugging = false;
			CurrentPID = -1;

			return true;
		}

		Logger::Error("DetachProcess(): ptrace(PT_DETACH) failed with error %llX %s\n", __error(), strerror(errno));
		return false;
	}

	// Reset vars.
	IsDebugging = false;
	CurrentPID = -1;

	// Kill the current proc monitor.
	DebuggeeMonitor.reset();

	return true;
}

bool Debug::SuspendDebug()
{
	int res = ptrace(PT_CONTINUE, CurrentPID, (void*)1, SIGSTOP);
	if (res != 0)
	{
		Logger::Error("Debug::Stop(): ptrace(PT_CONTINUE) SIGSTOP failed with error %llX %s\n", __error(), strerror(errno));
		return false;
	}

	int status;
	while (wait4(CurrentPID, &status, WNOHANG, nullptr) != CurrentPID)
		continue;

	return true;
}

void Debug::ResumeDebug()
{
	int res = ptrace(PT_CONTINUE, CurrentPID, (void*)1, 0);
	if (res != 0)
	{
		Logger::Error("Debug::Resume(): ptrace(PT_CONTINUE) SIGCONTINUE failed with error %llX %s\n", __error(), strerror(errno));
		return;
	}
}

void Debug::Stop(SceNetId sock)
{
	int pid;
	if (!Sockets::RecvInt(sock, &pid))
	{
		Logger::Error("ParseDebugTrace(): Failed to recieve the pid\n");
		SendStatePacket(sock, false, "Failed to recieve the pid.");
		return;
	}
	
	int res = ptrace(PT_CONTINUE, pid, (void*)1, SIGSTOP);
	if (res != 0)
	{
		Logger::Error("Stop(): ptrace(PT_CONTINUE) SIGSTOP failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "Continue failed: %llX %s", __error(), strerror(errno));
		return;
	}

	SendStatePacket(sock, true, "");
}

void Debug::Kill(SceNetId sock)
{
	int pid;
	if (!Sockets::RecvInt(sock, &pid))
	{
		Logger::Error("ParseDebugTrace(): Failed to recieve the pid\n");
		SendStatePacket(sock, false, "Failed to recieve the pid.");
		return;
	}

	int res = ptrace(PT_CONTINUE, pid, (void*)1, SIGKILL);
	if (res != 0)
	{
		Logger::Error("Kill(): ptrace(PT_CONTINUE) SIGKILL failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "Continue failed: %llX %s", __error(), strerror(errno));
		return;
	}

	SendStatePacket(sock, true, "");
}

void Debug::Resume(SceNetId sock)
{
	int pid;
	if (!Sockets::RecvInt(sock, &pid))
	{
		Logger::Error("ParseDebugTrace(): Failed to recieve the pid\n");
		SendStatePacket(sock, false, "Failed to recieve the pid.");
		return;
	}

	int res = ptrace(PT_CONTINUE, pid, (void*)1, 0);
	if (res != 0)
	{
		Logger::Error("Resume(): ptrace(PT_CONTINUE) SIGCONTINUE failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "Continue failed: %llX %s", __error(), strerror(errno));
		return;
	}

	SendStatePacket(sock, true, "");
}

void Debug::GetThreadInfo(SceNetId sock)
{
	if (!CheckDebug(sock))
		return;

	int threadId;
	Sockets::RecvInt(sock, &threadId);

	std::unique_ptr<OrbisThreadInfo> threadInfo = std::make_unique<OrbisThreadInfo>();
	threadInfo->Handle = threadId;

	char threadName[0x40];
	if (sceKernelGetThreadName(threadId, threadName) == 0)
	{
		strcpy(threadInfo->Name, threadName);
	}

	ThreadInfoPacket packet;
	packet.set_name(threadInfo->Name);
	packet.set_tid(threadId);

	SendProtobufPacket(sock, packet);
}


void Debug::GetThreadRegisters(SceNetId sock)
{
	if (!CheckDebug(sock))
		return;

	int threadId;
	Sockets::RecvInt(sock, &threadId);

	Registers regs;
	int res = ptrace(PT_GETREGS, threadId, &regs, 0);
	if (res == -1 && errno)
	{
		Logger::Error("GetThreadRegisters(): ptrace(PT_GETREGS) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "GetRegisters failed: %llX %s", __error(), strerror(errno));
		return;
	}

	Sockets::SendLargeData(sock, reinterpret_cast<unsigned char*>(&regs), sizeof(Registers));

	SendStatePacket(sock, true, "");
}

void Debug::SetThreadRegisters(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	int threadId;
	Sockets::RecvInt(sock, &threadId);

	if (threadId == 0)
	{
		Logger::Error("SetThreadRegisters(): Thread id was null");
		SendStatePacket(sock, false, "Thread id was null");
		return;
	}

	Registers regs;
	Sockets::RecvLargeData(sock, reinterpret_cast<unsigned char*>(&regs), sizeof(Registers));

	int res = ptrace(PT_SETREGS, threadId, &regs, 0);
	if (res == -1 && errno)
	{
		Logger::Error("SetThreadRegisters(): ptrace(PT_SETREGS) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "SetRegisters failed: %llX %s", __error(), strerror(errno));
		return;
	}

	SendStatePacket(sock, true, "");
}

void Debug::GetThreadList(SceNetId sock)
{
	ThreadListPacket packet;

	if (!Debug::CheckDebug(sock))
		return;

	int pid = Debug::CurrentPID;

	int rlwps = ptrace(PT_GETNUMLWPS, pid, nullptr, 0);
	if (rlwps == -1)
	{
		Logger::Error("GetThreadList(): ptrace(PT_GETNUMLWPS) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "GETNUMLWPS failed: %llX %s", __error(), strerror(errno));
		return;
	}

	std::unique_ptr<uint32_t[]> lwpids = std::make_unique<uint32_t[]>(rlwps);

	int res = ptrace(PT_GETLWPLIST, pid, lwpids.get(), rlwps);
	if (res == -1)
	{
		Logger::Error("GetThreadList(): ptrace(PT_GETLWPLIST) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "PT_GETLWPLIST failed: %llX %s", __error(), strerror(errno));
		return;
	}

	std::vector<ThreadInfoPacket> vectorList;
	
	for (int i = 0; i < rlwps; i++)
	{
		char name[256];
		sceKernelGetThreadName(lwpids[i], name);

		ThreadInfoPacket threadInfo;
		threadInfo.set_tid(lwpids[i]);
		threadInfo.set_name(name);

		vectorList.push_back(threadInfo);
	}
	*packet.mutable_threads() = { vectorList.begin(), vectorList.end() };

	SendProtobufPacket(sock, packet);
}

void Debug::SetSingleStep(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	int res = ptrace(PT_STEP, CurrentPID, (void*)1, 0);
	if (res == -1 && errno)
	{
		Logger::Error("SetSingleStep(): ptrace(PT_STEP) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "PT_STEP failed: %llX %s", __error(), strerror(errno));
		return;
	}

	SendStatePacket(sock, true, "");
}

void Debug::StopThread(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	int threadId;
	Sockets::RecvInt(sock, &threadId);

	if (threadId == 0)
	{
		Logger::Error("StopThread(): Thread id was null");
		SendStatePacket(sock, false, "Thread id was null");
		return;
	}

	int r = ptrace(PT_SUSPEND, threadId, nullptr, 0);
	if (r == -1)
	{
		Logger::Error("StopThread(): ptrace(PT_SUSPEND) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "PT_SUSPEND failed: %llX %s", __error(), strerror(errno));
		return;
	}

	SendStatePacket(sock, true, "");
}

void Debug::ResumeThread(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	int threadId;
	Sockets::RecvInt(sock, &threadId);

	if (threadId == 0)
	{
		Logger::Error("ResumeThread(): Thread id was null");
		SendStatePacket(sock, false, "Thread id was null");
		return;
	}

	int r = ptrace(PT_RESUME, threadId, nullptr, 0);
	if (r == -1)
	{
		Logger::Error("ResumeThread(): ptrace(PT_RESUME) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "PT_RESUME failed: %llX %s", __error(), strerror(errno));
		return;
	}

	SendStatePacket(sock, true, "");
}

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
			Logger::Error("SetWatchpoint(): matching watchpoint is already set\n");
			SendStatePacket(sock, false, "Failed to set watchpoint (already set)");
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
		}
	}

	SendStatePacket(sock, true, "");
}

void Debug::GetBreakpointList(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	auto CurrentBreakpoint = DebuggeeMonitor->Breakpoints;

	BreakpointListPacket packet;

	std::vector<BreakpointPacket> watchpoints(CurrentBreakpoint.size());

	for (int i = 0; i < CurrentBreakpoint.size(); i++)
	{
		watchpoints[i].set_index(CurrentBreakpoint[i]->Index);
		watchpoints[i].set_enabled(CurrentBreakpoint[i]->Enabled);
		watchpoints[i].set_address(CurrentBreakpoint[i]->Address);
	}

	*packet.mutable_breakpoints() = { watchpoints.begin(), watchpoints.end() };

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
		SendStatePacket(sock, false, "Failed to recieve watchpoint data");
	}

	int Index = breakpoint.index();
	uint64_t Address = breakpoint.address();
	bool Enabled = breakpoint.enabled();

	uint8_t original;
	ReadWriteMemory(CurrentPID, reinterpret_cast<void*>(Address), &original, sizeof(uint8_t), false);

	uint8_t bp_inst = 0xCC;
	ReadWriteMemory(CurrentPID, reinterpret_cast<void*>(Address), &bp_inst, sizeof(uint8_t), true);

	Logger::Success("Set breakpoint at 0x%016llX\n", Address);

	std::shared_ptr<Breakpoint> current = std::make_shared<Breakpoint>(Index, Enabled, Address, original);
	DebuggeeMonitor->Breakpoints.push_back(current);
}

void Debug::RemoveBreakpoint(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;

	BreakpointPacket breakpoint;
	if (!RecieveProtoBuf(sock, &breakpoint))
	{
		Logger::Error("SetBreakpoint(): failed with recieve breakpoint data\n");
		SendStatePacket(sock, false, "Failed to recieve watchpoint data");
	}

	auto Breakpoints = DebuggeeMonitor->Breakpoints;

	for (int i = 0; i < Breakpoints.size(); i++)
	{
		auto current = Breakpoints[i];
		if (current->IsSet(breakpoint))
		{
			ReadWriteMemory(CurrentPID, reinterpret_cast<void*>(current->Address), &current->Original, sizeof(uint8_t), true);

			Logger::Info("Removing breakpoint at 0x%016llX\n", current->Address);

			Breakpoints.erase(Breakpoints.begin() + i);
		}
	}
}

void Debug::SetProcessProt(SceNetId sock)
{
	if (!Debug::CheckDebug(sock))
		return;
	
	SetProcessProtPacket protPacket;
	if (!RecieveProtoBuf(sock, &protPacket))
	{
		Logger::Error("SetProcessProt(): failed with recieve prot packet\n");
		SendStatePacket(sock, false, "Failed to recieve prot packet");
	}

	SetProcessProtect(CurrentPID, protPacket.address(), protPacket.size(), protPacket.prot());

	SendStatePacket(sock, true, "");
}