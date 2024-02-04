#include "stdafx.h"
#include "ProcessMonitor.h"
#include "Debug.h"
#include "Events.h"
#include "PtraceDefs.h"
#include "SignalDefs.h"
#include <KernelInterface.h>
#include <KernelExt.h>

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
	if(!Sockets::RecvInt(sock, &threadId))
	{		
		Logger::Error("GetThreadRegisters(): failed to recieve thread id\n");
		SendStatePacket(sock, false, "GetRegisters failed to recieve thread id");
		return;
	}

	Registers registers;
	int res = ptrace(PT_GETREGS, threadId, &registers, 0);
	if (res == -1 && errno)
	{
		Logger::Error("GetThreadRegisters(): ptrace(PT_GETREGS) failed with error %llX %s\n", __error(), strerror(errno));
		SendStatePacket(sock, false, "GetRegisters failed: %llX %s", __error(), strerror(errno));
		return;
	}

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

	SendProtobufPacket(sock, registersPacket);
}

void Debug::SetThreadRegisters(SceNetId sock)
{
	if (!CheckDebug(sock))
		return;

	int threadId;
	if (!Sockets::RecvInt(sock, &threadId))
	{
		Logger::Error("GetThreadRegisters(): failed to recieve thread id\n");
		SendStatePacket(sock, false, "GetRegisters failed to recieve thread id");
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

	if (!CheckDebug(sock))
		return;

	int pid = CurrentPID;

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
