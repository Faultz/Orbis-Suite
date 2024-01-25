using OrbisLib2.Common.API;
using OrbisLib2.Common.Helpers;
using System;
using System.ComponentModel;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using static SQLite.SQLite3;

namespace OrbisLib2.Targets
{
    public enum WatchpointLength : uint
    {
        DR7_BYTE = 0,
        DR7_SHORT = 1,
        DR7_INT = 3,
        DR7_ULONG = 2,
    };

    public enum WatchpointType : uint
    {
        DR7_EXEC = 0x0,
        DR7_WRITE = 0x1,
        DR7_RW = 0x3
    };

    public record LibraryInfo(long Handle, string Path, ulong MapBase, ulong TextSize, ulong MapSize, ulong DataBase, ulong dataSize);
    public record PageInfo(string Name, ulong Start, ulong End, ulong Offset, ulong Size, uint Prot);

    public class Debug
    {
        private Target Target;

        public Debug(Target Target)
        {
            this.Target = Target;
        }

        public async Task<bool> IsDebugging()
        {
            (var result, var currentTarget) = await GetCurrentProcessId();

            if (!result.Succeeded)
                return false;

            if (currentTarget == -1)
                return false;

            return true;
        }

        public async Task<ResultState> Stop(int pid)
        {
            return await API.SendCommand(Target, 1000, APICommand.ApiDbgBreak, async (Socket Sock) =>
            {
                await Sock.SendInt32Async(pid);

                return new ResultState { Succeeded = true };
            });
        }
        public async Task<ResultState> Kill(int pid)
        {
            return await API.SendCommand(Target, 1000, APICommand.ApiDbgKill, async (Socket Sock) =>
            {
                await Sock.SendInt32Async(pid);

                return new ResultState { Succeeded = true };
            });
        }
        public async Task<ResultState> Resume(int pid)
        {
            return await API.SendCommand(Target, 1000, APICommand.ApiDbgResume, async (Socket Sock) =>
            {
                await Sock.SendInt32Async(pid);

                return new ResultState { Succeeded = true };
            });
        }

        public async Task<ResultState> SetWatchpoint(int index, ulong address, WatchpointLength length, WatchpointType type)
        {
            return await API.SendCommand(Target, 1000, APICommand.ApiDbgWatchpointSet, async (Socket Sock) =>
            {
                var result = await API.SendNextPacket(Sock, new WatchpointPacket { Index = (uint)index, Enabled = true, Address = address,  Length = (uint)length, Type = (uint)type });

                return new ResultState { Succeeded = true };
            });
        }

        public async Task<ResultState> RemoveWatchpoint(int index, ulong address)
        {
            return await API.SendCommand(Target, 1000, APICommand.ApiDbgWatchpointRemove, async (Socket Sock) =>
            {
                var result = await API.SendNextPacket(Sock, new WatchpointPacket { Index = (uint)index, Enabled = false, Address = address, Length = 0, Type = 0 });

                return new ResultState { Succeeded = true };
            });
        }
        public async Task<(ResultState, List<ThreadInfoPacket>)> GetThreadList()
        {
            var tempThreadList = new List<ThreadInfoPacket>();

            var result = await API.SendCommand(Target, 1000, APICommand.ApiDbgThreadList, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    var rawPacket = await Sock.ReceiveSizeAsync();
                    var Packet = ThreadListPacket.Parser.ParseFrom(rawPacket);

                    if (Packet.Threads.Count == 0)
                        return new ResultState { Succeeded = false, ErrorMessage = $"Packet returned with a empty thread count: {Packet.Threads.Count}" };

                    foreach(var thread in Packet.Threads)
                    {
                        ThreadInfoPacket threadInfo = new ThreadInfoPacket { TID = thread.TID, Name = thread.Name };
                        tempThreadList.Add(threadInfo);
                    }

                    return new ResultState { Succeeded = true };
                }
            });

            return (result, tempThreadList);
        }

        public async Task<(ResultState, string)> GetThreadName(int lwpid)
        {
            string threadName = "";

            var result = await API.SendCommand(Target, 1000, APICommand.ApiExtGetThreadInfo, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    await Sock.SendInt32Async(lwpid);

                    var rawPacket = await Sock.ReceiveSizeAsync();
                    var Packet = ThreadInfoPacket.Parser.ParseFrom(rawPacket);

                    if (Packet.Name.Length == 0)
                        return new ResultState { Succeeded = false, ErrorMessage = $"Thread name is empty" };

                    threadName = Packet.Name;

                    return new ResultState { Succeeded = true };
                }
            });

            return (result, threadName);
        }

        public async Task<ResultState> Attach(int pid)
        {
            return await API.SendCommand(Target, 1000, APICommand.ApiDbgAttach, async (Socket Sock) =>
            {
                await Sock.SendInt32Async(pid);

                return await API.GetState(Sock);
            });
        }

        public async Task<ResultState> Detach()
        {
            return await API.SendCommand(Target, 400, APICommand.ApiDbgDetach, async (Socket Sock) =>
            {
                return await API.GetState(Sock);
            });
        }

        public async Task<(ResultState, int ProcessId)> GetCurrentProcessId()
        {
            var tempProcessId = -1;
            var result = await API.SendCommand(Target, 400, APICommand.ApiDbgGetCurrent, async (Socket Sock) =>
            {
                tempProcessId = await Sock.RecvInt32Async();

                return new ResultState { Succeeded = true };
            });

            return (result, tempProcessId);
        }

        public async Task<(ResultState, ProcInfo)> GetCurrentProcess()
        {
            // Check if were debugging.
            (var result, var currentProcessId) = await GetCurrentProcessId();

            if (!result.Succeeded || currentProcessId == -1)
                return (result, null);

            // Pull the process list.
            (result, var procList) = await Target.GetProcList();

            // If for what ever reason getting the proc list fails just abort.
            if (!result.Succeeded)
                return (result, null);

            // Try to find the process in the process list and if by some reason we cant abort.
            var proc = procList.Find(x => x.ProcessId == currentProcessId);
            if (proc == null)
                return (new ResultState { Succeeded = false }, null); ;

            return (result, proc);
        }

        public async Task<(ResultState, int)> LoadLibrary(string Path)
        {
            int tempHandle = -1;

            var result = await API.SendCommand(Target, 4000, APICommand.ApiDbgLoadLibrary, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    var result = await API.SendNextPacket(Sock, new SPRXPacket { Path = Path });

                    if (result.Succeeded)
                        tempHandle = await Sock.RecvInt32Async();

                    return result;
                }
            });

            return (result, tempHandle);
        }

        public async Task<ResultState> UnloadLibrary(int Handle)
        {
            return await API.SendCommand(Target, 4000, APICommand.ApiDbgUnloadLibrary, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                    return await API.SendNextPacket(Sock, new SPRXPacket { Handle = Handle });
            });
        }

        public async Task<(ResultState, int)> ReloadLibrary(int Handle, string Path)
        {
            int tempHandle = -1;
            var result = await API.SendCommand(Target, 4000, APICommand.ApiDbgReloadLibrary, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    var result = await API.SendNextPacket(Sock, new SPRXPacket { Path = Path, Handle = Handle });
                    tempHandle = Sock.RecvInt32();

                    return result;
                }
            });

            return (result, tempHandle);
        }

        public async Task<(ResultState, List<LibraryInfo>)> GetLibraries()
        {
            var tempLibraryList = new List<LibraryInfo>();

            var result = await API.SendCommand(Target, 400, APICommand.ApiDbgLibraryList, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    var rawPacket = await Sock.ReceiveSizeAsync();
                    var Packet = LibraryListPacket.Parser.ParseFrom(rawPacket);

                    foreach(var library in Packet.Libraries)
                    {
                        tempLibraryList.Add(new LibraryInfo(library.Handle, library.Path, library.MapBase, library.MapSize, library.TextSize, library.DataBase, library.TextSize));
                    }

                    return new ResultState { Succeeded = true };
                }
            });

            return (result, tempLibraryList);
        }

        public async Task<(ResultState, List<PageInfo>)> GetPages()
        {
            var tempLibraryList = new List<PageInfo>();

            var result = await API.SendCommand(Target, 400, APICommand.ApiExtGetPages, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    var rawPacket = await Sock.ReceiveSizeAsync();
                    var Packet = PagesListPacket.Parser.ParseFrom(rawPacket);

                    foreach (var page in Packet.Pages)
                    {
                        tempLibraryList.Add(new PageInfo(page.Name, page.Start, page.End, page.Offset, page.Size, page.Prot));
                    }

                    return new ResultState { Succeeded = true };
                }
            });

            return (result, tempLibraryList);
        }

        public async Task<(ResultState, byte[])> ReadMemory(ulong address, ulong length)
        {
            var tempData = new byte[length];
            var result = await API.SendCommand(Target, 1000, APICommand.ApiDbgRead, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    var result = await API.SendNextPacket(Sock, new RWPacket { Address = address, Length = length });

                    if (result.Succeeded)
                        await Sock.RecvLargeAsync(tempData);

                    return result;
                }
            });

            return (result, tempData);
        }

        public async Task<ResultState> WriteMemory(ulong Address, byte[] Data)
        {
            return await API.SendCommand(Target, 2000, APICommand.ApiDbgWrite, async (Socket Sock) =>
            {
                if (await Sock.RecvInt32Async() != 1)
                    return new ResultState { Succeeded = false, ErrorMessage = $"The target {Target.Name} ({Target.IPAddress}) is not currently debugging any process." };
                else
                {
                    var result = await API.SendNextPacket(Sock, new RWPacket { Address = Address, Length = (ulong)Data.Length });

                    if (result.Succeeded)
                    {
                        await Sock.SendLargeAsync(Data);

                        result = await API.GetState(Sock);
                    }

                    return result;
                }
            });
        }
    }
}
