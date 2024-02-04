#include "stdafx.h"
#include "ProcessMonitor.h"
#include "SignalDefs.h"
#include "PtraceDefs.h"
#include "Debug.h"
#include "KernelInterface.h"

#include "APIPackets.pb.h"

ProcessMonitor::ProcessMonitor(int pid)
{
	ShouldRun = true;

	ThreadPool::QueueJob([=] { WatchThread(pid); });
}

ProcessMonitor::~ProcessMonitor()
{
	ShouldRun = false;

	Clear(0);
}

void ProcessMonitor::Clear(int signal)
{
	if (signal != 0)
	{
		for (int i = 0; i < Breakpoints.size(); i++)
		{
			auto Current = Breakpoints[i];
			ReadWriteMemory(Debug::CurrentPID, reinterpret_cast<void*>(Current->Address), &Current->Original, 1, true);
		}

		int rlwps = ptrace(PT_GETNUMLWPS, Debug::CurrentPID, nullptr, 0);
		if (rlwps == -1)
		{
			Logger::Error("~ProcessMonitor(): ptrace(PT_GETNUMLWPS) failed with error %llX %s\n", __error(), strerror(errno));
			return;
		}

		std::unique_ptr<uint32_t[]> lwpids = std::make_unique<uint32_t[]>(rlwps);
		int res = ptrace(PT_GETLWPLIST, Debug::CurrentPID, lwpids.get(), rlwps);
		if (res == -1)
		{
			Logger::Error("~ProcessMonitor(): ptrace(PT_GETLWPLIST) failed with error %llX %s\n", __error(), strerror(errno));
			return;
		}

		for (int i = 0; i < rlwps; i++)
		{
			WatchpointData watchData;
			memset(&watchData, 0, sizeof(watchData));

			res = ptrace(PT_SETDBREGS, lwpids[i], &watchData, 0);
			if (res == -1 && errno)
			{
				Logger::Error("~ProcessMonitor(): [lwpid][%i] ptrace(PT_SETDBREGS) failed with error %llX %s\n", lwpids[i], __error(), strerror(errno));
				return;
			}
		}
	}

	Breakpoints.clear();
	Watchpoints.clear();
}

void ProcessMonitor::WatchThread(int pid)
{
	while (ShouldRun)
	{
		std::vector<kinfo_proc> procList;
		GetProcessList(procList);

		if (std::find_if(procList.begin(), procList.end(), [=](const kinfo_proc& arg) { return arg.pid == pid; }) == procList.end())
		{
			Logger::Error("Proc %d has died.\n", pid);

			if (OnExit != nullptr)
				OnExit();

			return;
		}

		int status;
		auto debuggeePid = wait4(pid, &status, WNOHANG, nullptr);
		if (debuggeePid == pid)
		{
			int signal = WSTOPSIG(status);
			Logger::Error("Process %d has recieved the signal %d\n", pid, signal);

			if (signal == SIGTRAP)
			{
				if (OnInterrupt != nullptr)
					OnInterrupt(signal, pid);
			}
			else
			{
				if (OnException != nullptr)
					OnException(status);
			}
		}

		sceKernelSleep(1);
	}
}