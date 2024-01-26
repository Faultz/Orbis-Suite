#include "stdafx.h"
#include "ProcessMonitor.h"
#include "SignalDefs.h"
#include "PtraceDefs.h"
#include "Debug.h"
#include "KernelInterface.h"

struct ptrace_lwpinfo
{
	uint32_t lwpid;
	char _0x04[0x7C];
	char name[24];
};

std::vector<std::string> regNames = {
	"r15",
	"r14",
	"r13",
	"r12",
	"r11",
	"r10",
	"r9",
	"r8",
	"rdi",
	"rsi",
	"rbp",
	"rbx",
	"rdx",
	"rcx",
	"rax",
	"trapno",
	"fs",
	"gs",
	"err",
	"es",
	"ds",
	"rip",
	"cs",
	"rflags",
	"rsp",
	"ss"
};

ProcessMonitor::ProcessMonitor(int pid)
{
	ShouldRun = true;

	ThreadPool::QueueJob([=] { WatchThread(pid); });
}

ProcessMonitor::~ProcessMonitor()
{
	ShouldRun = false;
}

void WriteRegister(std::string regName, uint64_t reg, std::unique_ptr<OrbisProcessPage[]>& pages, int count)
{
	std::string libraryName = "";
	int protection = 0;
	for (int i = 0; i < count; i++)
	{
		if (reg >= pages[i].Start && reg <= pages[i].End) {
			// The register is in the range of this page
			libraryName = pages[i].Name;
			protection = pages[i].Prot;
		}
	}
	printf("%-14s 0x%016lX - %-24s", regName.data(), (unsigned long long)reg, libraryName.data());

	if (protection != 0)
	{
		scePthreadAttrGetstackaddr
		printf("Protection: ");
		if (protection & SCE_KERNEL_PROT_CPU_READ)
			printf("Read ");
		if (protection & SCE_KERNEL_PROT_CPU_RW)
			printf("Write ");
		if (protection & SCE_KERNEL_PROT_CPU_EXEC)
			printf("Execute");
	}

	printf("\n");
}

void ProcessException(int lwpid, Registers registers)
{
	// get pages to check
	auto pages = std::make_unique<OrbisProcessPage[]>(1000);
	int actualCount = GetPages(Debug::CurrentPID, pages.get(), 1000);

	for (int i = 0; i < regNames.size(); i++)
	{
		WriteRegister(regNames[i], registers.regs[i], pages, actualCount);
	}
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

			std::unique_ptr<ptrace_lwpinfo> lwpinfo = std::make_unique<ptrace_lwpinfo>();
			int r = ptrace(PT_LWPINFO, pid, lwpinfo.get(), sizeof(ptrace_lwpinfo));
			if (r != 0)
			{
				Logger::Error("Failed to read lwpinfo\n");
			}

			Logger::Error("name:(%i) %s\n", lwpinfo->lwpid, lwpinfo->name);

			int lwpid = lwpinfo->lwpid;

			Registers registers;
			r = ptrace(PT_GETREGS, lwpid, &registers, 0);
			if (r == -1 && errno)
			{
				Logger::Error("Failed to read registers\n");
			}

			Logger::Info("Registers:");

			ProcessException(lwpid, registers);

			//if (OnException != nullptr)
			//	OnException(status);
		}

		sceKernelSleep(1);
	}
}