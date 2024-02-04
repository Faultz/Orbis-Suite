#include "stdafx.h"

#include "ProcessMonitor.h"
#include "Debug.h"
#include "Events.h"
#include "PtraceDefs.h"
#include "SignalDefs.h"
#include <KernelInterface.h>
#include <KernelExt.h>

std::mutex Debug::DebugMtx;
bool Debug::IsDebugging;
int Debug::CurrentPID;
std::shared_ptr<ProcessMonitor> Debug::DebuggeeMonitor;
WatchpointData Debug::WatchData;

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
		DebuggeeMonitor->OnException = OnException; // Fired when the process being debugged encounters an exception.
		DebuggeeMonitor->OnInterrupt = OnInterrupt; // Fired when the process being debugged hits a trap
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


void Debug::PrintRegister(std::string regName, uint64_t reg, std::unique_ptr<OrbisProcessPage[]>& pages, int count)
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

void Debug::LogInterrupt(int lwpid, Registers registers)
{
	// get pages to check
	auto pages = std::make_unique<OrbisProcessPage[]>(1000);
	int actualCount = GetPages(Debug::CurrentPID, pages.get(), 1000);

	for (int i = 0; i < 25; i++)
	{
		PrintRegister(std::get<0>(registerCollection[i]), *(uint64_t*)((uint64_t)&registers + std::get<1>(registerCollection[i])), pages, actualCount);
	}
}

void Debug::OnExit()
{
	Logger::Info("Process %d has died!\n", CurrentPID);

	DebuggeeMonitor->Clear(0);

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

	DebuggeeMonitor->Clear(signal);

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

void Debug::OnInterrupt(int status, int pid)
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

	LogInterrupt(lwpid, registers);

	Breakpoint* breakpoint = nullptr;
	for (int i = 0; i < DebuggeeMonitor->Breakpoints.size(); i++)
	{
		auto current = DebuggeeMonitor->Breakpoints[i];
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

			if (DebuggeeMonitor->OnException != nullptr)
				DebuggeeMonitor->OnException(status);
		}

		res = ptrace(PT_STEP, lwpid, (void*)1, 0);
		if (res == -1 && errno)
		{
			Logger::Error("[Breakpoint] Single step failed\n");

			if (DebuggeeMonitor->OnException != nullptr)
				DebuggeeMonitor->OnException(status);
		}

		while (!wait4(pid, &status, WNOHANG, nullptr))
		{
			sceKernelSleep(1);
		}

		uint8_t bp_inst = 0xCC;
		ReadWriteMemory(pid, reinterpret_cast<void*>(Address), &bp_inst, sizeof(uint8_t), true);

		Logger::Info("Software breakpoint handled at 0x%016llX\n", Address);
	}

	std::shared_ptr<DebuggerInterruptPacket> packet = std::make_shared<DebuggerInterruptPacket>();
	packet->set_threadid(lwpid);
	packet->set_status(status);
	packet->set_name(lwpinfo->name);

	RegistersPacket registersPacket;
	registersPacket.set_r15(registers.r_r15);
	registersPacket.set_r14(registers.r_r14);
	registersPacket.set_r13(registers.r_r13);
	registersPacket.set_r12(registers.r_r12);
	registersPacket.set_r11(registers.r_r11);
	registersPacket.set_r10(registers.r_r10);
	registersPacket.set_r9(registers.r_r9);
	registersPacket.set_r8(registers.r_r8);
	registersPacket.set_rdi(registers.r_rdi);
	registersPacket.set_rsi(registers.r_rsi);
	registersPacket.set_rbp(registers.r_rbp);
	registersPacket.set_rbx(registers.r_rbx);
	registersPacket.set_rdx(registers.r_rdx);
	registersPacket.set_rcx(registers.r_rcx);
	registersPacket.set_rax(registers.r_rax);
	registersPacket.set_trapno(registers.r_trapno);
	registersPacket.set_fs(registers.r_fs);
	registersPacket.set_gs(registers.r_gs);
	registersPacket.set_err(registers.r_err);
	registersPacket.set_es(registers.r_es);
	registersPacket.set_ds(registers.r_ds);
	registersPacket.set_rip(registers.r_rip);
	registersPacket.set_cs(registers.r_cs);
	registersPacket.set_rflags(registers.r_rflags);
	registersPacket.set_rsp(registers.r_rsp);
	registersPacket.set_ss(registers.r_ss);

	*packet->mutable_registers() = registersPacket;

	Events::SendEvent(Events::EVENT_EXCEPTION, pid, &packet);
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

	// Kill the current proc monitor.
	DebuggeeMonitor.reset();

	CurrentPID = -1;

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
	if (!CheckDebug(sock))
		return;

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
	if (!CheckDebug(sock))
		return;

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
	if (!CheckDebug(sock))
		return;

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

void Debug::SetSingleStep(SceNetId sock)
{
	if (!CheckDebug(sock))
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