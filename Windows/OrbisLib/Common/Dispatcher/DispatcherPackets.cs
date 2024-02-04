﻿using OrbisLib2.Common.Database.Types;
using Google.Protobuf;
using System;

namespace OrbisLib2.Common.Dispatcher
{
    [Serializable]
    internal sealed class DispatcherClientPacket
    {
        public enum PacketType
        {
            None,
            NewClient,
            RemoveClient,
            HeartBeat
        };

        public PacketType Type { get; set; }
        public string? ClientName { get; set; }
        public int Port { get; set; }

        public DispatcherClientPacket() { }

        public DispatcherClientPacket(PacketType Type, string ClientName, int Port)
        {
            this.Type = Type;
            this.ClientName = ClientName;
            this.Port = Port;
        }
    }

    [Serializable]
    public class TitleChange
    {
        public string? TitleID { get; set; }
    }

    [Serializable]
    public class Print
    {
        public string? Sender { get; set; }
        public string? Data { get; set; }
    }

    [Serializable]
    public class SerialCom
    {
        public byte[]? Data { get; set; }
    }

    [Serializable]
    public class Registers
    {
        public ulong r15 { get; set; }
        public ulong r14 { get; set; }
        public ulong r13 { get; set; }
        public ulong r12 { get; set; }
        public ulong r11 { get; set; }
        public ulong r10 { get; set; }
        public ulong r9 { get; set; }
        public ulong r8 { get; set; }
        public ulong rdi { get; set; }
        public ulong rsi { get; set; }
        public ulong rbp { get; set; }
        public ulong rbx { get; set; }
        public ulong rdx { get; set; }
        public ulong rcx { get; set; }
        public ulong rax { get; set; }
        public uint trapno { get; set; }
        public uint fs { get; set; }
        public uint gs { get; set; }
        public ulong err { get; set; }
        public uint es { get; set; }
        public uint ds { get; set; }
        public ulong rip { get; set; }
        public ulong cs { get; set; }
        public ulong rflags { get; set; }
        public ulong rsp { get; set; }
        public ulong ss { get; set; }
    }

    [Serializable]
    public class DebuggerInterrupt
    {
        public uint ThreadId { get; set; }
        public uint Status { get; set; }
        public string Name { get; set; }
        public Registers Registers { get; set; }
    }


    [Serializable]
    public class Break
    {
        public int? Reason { get; set; }

        public DebuggerInterrupt? Interrupt { get; set; }
    }

    [Serializable]
    public class TargetStatus
    {
        public TargetStatusType PreviousState { get; set; }

        public TargetStatusType NewState { get; set; }
    }

    [Serializable]
    public class ForwardPacket
    {
        public enum PacketType
        {
            None,

            // Debugging
            Print,
            SerialCom,
            Intercept,
            Continue,

            // Process States
            ProcessDie,
            ProcessAttach,
            ProcessDetach,

            // Target State
            TargetSuspend,
            TargetResume,
            TargetShutdown,
            TargetStateChanged,

            // Misc
            DBTouched,
            MutableInfoUpdated,
        };

        /// <summary>
        /// The event the packet is firing for.
        /// </summary>
        public PacketType Type { get; set; }

        /// <summary>
        /// The Target's IP Address which the Event belongs to.
        /// </summary>
        public string? SenderIPAddress { get; set; }

        /// <summary>
        /// The process id for the event triggered.
        /// </summary>
        public int ProcessId { get; set; }

        public TitleChange? TitleChange { get; set; }

        public Print? Print { get; set; }

        public SerialCom? SerialCom { get; set; }

        public Break? Break { get; set; }

        public TargetStatus? TargetStatus { get; set; }

        public ForwardPacket(PacketType Type, string SenderIPAddress)
        {
            this.Type = Type;
            this.SenderIPAddress = SenderIPAddress;

            //TODO: Maybe add logic to the getter/setter so that it will create these...
            TitleChange = new TitleChange();
            Print = new Print();
            SerialCom = new SerialCom();
            Break = new Break();
            TargetStatus = new TargetStatus();
        }
    }
}
