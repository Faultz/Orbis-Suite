#pragma once

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

};

class ProcessMonitor
{
public:
	ProcessMonitor(int pid);
	~ProcessMonitor();

	std::vector<std::shared_ptr<Watchpoint>> Watchpoints;
	std::vector<std::shared_ptr<Breakpoint>> Breakpoints;

	std::function<void()> OnExit;
	std::function<void(int)> OnException;
private:
	bool ShouldRun;

	void WatchThread(int pid);
};
