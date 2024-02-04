#pragma once

struct Registers
{
	uint64_t r_r15;
	uint64_t r_r14;
	uint64_t r_r13;
	uint64_t r_r12;
	uint64_t r_r11;
	uint64_t r_r10;
	uint64_t r_r9;
	uint64_t r_r8;
	uint64_t r_rdi;
	uint64_t r_rsi;
	uint64_t r_rbp;
	uint64_t r_rbx;
	uint64_t r_rdx;
	uint64_t r_rcx;
	uint64_t r_rax;
	uint32_t r_trapno;
	uint16_t r_fs;
	uint16_t r_gs;
	uint32_t r_err;
	uint16_t r_es;
	uint16_t r_ds;
	uint64_t r_rip;
	uint64_t r_cs;
	uint64_t r_rflags;
	uint64_t r_rsp;
	uint64_t r_ss;
};

enum WatchpointLength : uint32_t
{
	DR7_BYTE = 0,
	DR7_SHORT = 1,
	DR7_INT = 3,
	DR7_ULONG = 2,
};

enum WatchpointType : uint32_t
{
	DR7_EXEC = 0,
	DR7_WRITE = 1,
	DR7_RW = 3
};

struct Watchpoint
{
	int Index;
	bool Enabled;
	uint64_t Address;
	WatchpointType Type;
	WatchpointLength Length;

	Watchpoint() {}
	Watchpoint(int index, bool enabled, uint64_t address, WatchpointType type, WatchpointLength length) 
		: Index(index), Enabled(enabled), Address(address), Type(type), Length(length) {}
};

struct WatchpointData
{
	uint64_t dr[16];
};

struct Breakpoint
{
	int Index;
	bool Enabled;
	uint64_t Address;
	uint8_t Original;
	int HitCount;

	Breakpoint() {}
	Breakpoint(int index, bool enabled, uint64_t address, uint8_t original)
		: Index(index), Enabled(enabled), Address(address), Original(original), HitCount(0) {}


	bool IsSet(BreakpointPacket packet)
	{
		return packet.index() == Index && Enabled;
	}
};

struct Interrupt
{
	uint32_t ThreadId;
	uint32_t Status;
	char Name[40];
	//Registers registers;
};

struct ptrace_lwpinfo
{
	uint32_t lwpid;
	char _0x04[0x7C];
	char name[24];
};

#undef offsetof
#define offsetof(s,m) ((::size_t)&reinterpret_cast<char const volatile&>((((s*)0)->m)))

#define REG(a, c) { std::tuple<std::string, int, int>{ #a, offsetof(Registers, Registers::r_##a), sizeof(c) } },

inline std::tuple<std::string, int, int> registerCollection[] = {
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

class ProcessMonitor
{
public:
	ProcessMonitor(int pid);
	~ProcessMonitor();

	void Clear(int signal);

	std::vector<std::shared_ptr<Watchpoint>> Watchpoints;
	std::vector<std::shared_ptr<Breakpoint>> Breakpoints;

	std::function<void()> OnExit;
	std::function<void(int)> OnException;
	std::function<void(int, int)> OnInterrupt;
private:
	bool ShouldRun;

	void WatchThread(int pid);
};
