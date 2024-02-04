#pragma once
#include "ProcessMonitor.h"
#include "KernelInterface.h"

#define	DR7_DISABLE       0x00
#define	DR7_LOCAL_ENABLE  0x01
#define	DR7_GLOBAL_ENABLE 0x02

#define	DR7_MASK(i) ((uint64_t)(0xf) << ((i) * 4 + 16) | 0x3 << (i) * 2)
#define	DR7_SET(i, len, access, enable) ((uint64_t)((len) << 2 | (access)) << ((i) * 4 + 16) | (enable) << (i) * 2)
#define	DR7_GD        0x2000
#define	DR7_ENABLED(d, i)	(((d) & 0x3 << (i) * 2) != 0)
#define	DR7_ACCESS(d, i)	((d) >> ((i) * 4 + 16) & 0x3)
#define	DR7_LEN(d, i)	((d) >> ((i) * 4 + 18) & 0x3)

class Debug
{
public:
	static bool IsDebugging;
	static int CurrentPID;

	static bool CheckDebug(SceNetId s);
	static void Attach(SceNetId sock);
	static void Detach(SceNetId Sock);
	static void Current(SceNetId sock);
	static void RWMemory(SceNetId Sock, bool write);

	// Ext
	static void Stop(SceNetId sock);
	static void Kill(SceNetId sock);
	static void Resume(SceNetId sock);

	static void GetThreadInfo(SceNetId sock);
	static void GetThreadRegisters(SceNetId sock);
	static void SetThreadRegisters(SceNetId sock);
	static void GetThreadList(SceNetId sock);

	static void SetSingleStep(SceNetId sock);

	static void StopThread(SceNetId sock);
	static void ResumeThread(SceNetId sock);

	static void GetWatchpointList(SceNetId sock);
	static void SetWatchpoint(SceNetId sock);
	static void RemoveWatchpoint(SceNetId sock);

	static void GetBreakpointList(SceNetId sock);
	static void SetBreakpoint(SceNetId sock);
	static void RemoveBreakpoint(SceNetId sock);

	static void SetProcessProt(SceNetId sock);
private:
	static std::mutex DebugMtx;
	static std::shared_ptr<ProcessMonitor> DebuggeeMonitor;
	static WatchpointData WatchData;

	static bool TryDetach(int pid);

	// Ext
	static bool SuspendDebug();
	static void ResumeDebug();

	// Logging
	static void PrintRegister(std::string regName, uint64_t reg, std::unique_ptr<OrbisProcessPage[]>& pages, int count);
	static void LogInterrupt(int lwpid, Registers registers);

	// Process Events
	static void OnExit();
	static void OnException(int status);
	static void OnInterrupt(int status, int pid);
};
