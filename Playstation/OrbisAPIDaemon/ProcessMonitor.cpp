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

#undef offsetof
#define offsetof(s,m) ((::size_t)&reinterpret_cast<char const volatile&>((((s*)0)->m)))

#define REG(a, c) { std::tuple<std::string, int, int>{ #a, offsetof(Registers, Registers::r_##a), sizeof(c) } },

std::tuple<std::string, int, int> registerCollection[] = {
	REG(r15, uint64_t)
	REG(r14, uint64_t)
	REG(r13, uint64_t)
	REG(r12, uint64_t)
	REG(r11, uint64_t)
	REG(r10, uint64_t)
	REG(r9, uint64_t)
	REG(r8, uint64_t)
	REG(rdi, uint64_t)
	REG(rsi, uint64_t)
	REG(rbp, uint64_t)
	REG(rdx, uint64_t)
	REG(rcx, uint64_t)
	REG(rax, uint64_t)
	REG(trapno, uint32_t)
	REG(fs, uint16_t)
	REG(gs, uint16_t)
	REG(err, uint32_t)
	REG(es, uint16_t)
	REG(ds, uint16_t)
	REG(rip, uint64_t)
	REG(cs, uint64_t)
	REG(rflags, uint64_t)
	REG(rsp, uint64_t)
	REG(ss, uint64_t)
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
	std::string pageName = "";
	int protection = 0;
	for (int i = 0; i < count; i++)
	{
		if (reg >= pages[i].Start && reg <= pages[i].End) {
			// The register is in the range of this page
			pageName = pages[i].Name;
			protection = pages[i].Prot;
		}
	}

	printf(" %-14s 0x%016lX - %-24s", regName.data(), (unsigned long long)reg, pageName.data());

	if (protection != 0)
	{
		
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

	for (int i = 0; i < 25; i++)
	{
		WriteRegister(std::get<0>(registerCollection[i]), *(uint64_t*)((uint64_t)&registers + std::get<1>(registerCollection[i])), pages, actualCount);
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

			if (signal == SIGTRAP)
			{
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

				Logger::Info("Registers:\n");

				ProcessException(lwpid, registers);

				Breakpoint* breakpoint;
				for (int i = 0; i < Breakpoints.size(); i++)
				{
					auto current = Breakpoints[i];
					if (current->Address == (registers.r_rip - 1))
						breakpoint = current.get();
				}

				if (breakpoint)
				{
					Logger::Info("Breakpoint hit at 0x%016llX\n", breakpoint->Address);

					uint64_t Address = breakpoint->Address;
					uint64_t Original = breakpoint->Original;

					ReadWriteMemory(pid, reinterpret_cast<void*>(Address), &Original, sizeof(uint8_t), true);

					registers.r_rip -= 1;
					int res = ptrace(PT_SETREGS, lwpid, &registers, 0);
					if (res == -1 && errno)
					{
						Logger::Error("[Breakpoint] Failed to set registers\n");

						if (OnException != nullptr)
							OnException(status);
					}

					res = ptrace(PT_STEP, lwpid, (void*)1, 0);
					if (res == -1 && errno)
					{
						Logger::Error("[Breakpoint] Single step failed\n");

						if (OnException != nullptr)
							OnException(status);
					}

					while (!wait4(pid, &status, WNOHANG, nullptr))
					{
						sceKernelSleep(4);
					}

					Logger::Info("Signal: %i\n", WSTOPSIG(status));

					uint8_t bp_inst = 0xCC;
					ReadWriteMemory(pid, reinterpret_cast<void*>(Address), &bp_inst, sizeof(uint8_t), true);
				}
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