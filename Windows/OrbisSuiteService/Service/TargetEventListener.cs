﻿using OrbisLib2.Common;
using OrbisLib2.Common.Helpers;
using System.Net.Sockets;
using OrbisLib2.Common.Dispatcher;
using System.Net;
using Microsoft.Extensions.Logging;
using System.Windows.Controls;

namespace OrbisSuiteService.Service
{
    public enum EventId
    {
        EVENT_EXCEPTION,
        EVENT_CONTINUE,
        EVENT_DIE,
        EVENT_ATTACH,
        EVENT_DETACH,
        EVENT_SUSPEND,
        EVENT_RESUME,
        EVENT_SHUTDOWN,
    };

    public class TargetEventListener
    {
        private Listener _TargetListener;
        private Dispatcher _Dispatcher;
        private ILogger _Logger;

        public TargetEventListener(Dispatcher Dispatcher, ILogger logger)
        {
            _Logger = logger;
            _Logger.LogInformation("TargetEventListener");
            _Dispatcher = Dispatcher;

            _TargetListener = new Listener(Config.EventPort);
            _TargetListener.SocketAccepted += _TargetListener_SocketAccepted;
            _TargetListener.Start();

            _Logger.LogInformation("TargetEventListener Done");
        }

        private void _TargetListener_SocketAccepted(Socket s)
        {
            var eventId = s.RecvInt32();
            _Logger.LogInformation($"{eventId}");
            var ipAddress = ((IPEndPoint)s.RemoteEndPoint).Address.ToString();
            switch (eventId)
            {
                default:
                    _Logger.LogWarning($"Unknown Event {eventId}");
                    break;

                case (int)EventId.EVENT_EXCEPTION:
                    var packet = new ForwardPacket(ForwardPacket.PacketType.Intercept, ipAddress);

                    var rawPacket = s.ReceiveSize();
                    var InterruptPacket = DebuggerInterruptPacket.Parser.ParseFrom(rawPacket);

                    packet.Break = new Break() { Reason = 0, Interrupt = InterruptPacket };

                    _Dispatcher.PublishEvent(packet);
                    break;

                case (int)EventId.EVENT_CONTINUE:
                    _Dispatcher.PublishEvent(new ForwardPacket(ForwardPacket.PacketType.Continue, ipAddress));
                    break;

                case (int)EventId.EVENT_DIE:
                    _Dispatcher.PublishEvent(new ForwardPacket(ForwardPacket.PacketType.ProcessDie, ipAddress));
                    break;

                case (int)EventId.EVENT_ATTACH:
                    packet = new ForwardPacket(ForwardPacket.PacketType.ProcessAttach, ipAddress);
                    packet.ProcessId = s.RecvInt32();
                    _Dispatcher.PublishEvent(packet);
                    break;

                case (int)EventId.EVENT_DETACH:
                    _Dispatcher.PublishEvent(new ForwardPacket(ForwardPacket.PacketType.ProcessDetach, ipAddress));
                    break;

                case (int)EventId.EVENT_SUSPEND:
                    _Dispatcher.PublishEvent(new ForwardPacket(ForwardPacket.PacketType.TargetSuspend, ipAddress));
                    break;

                case (int)EventId.EVENT_RESUME:
                    _Dispatcher.PublishEvent(new ForwardPacket(ForwardPacket.PacketType.TargetResume, ipAddress));
                    break;

                case (int)EventId.EVENT_SHUTDOWN:
                    _Dispatcher.PublishEvent(new ForwardPacket(ForwardPacket.PacketType.TargetShutdown, ipAddress));
                    break;
            }
        }
    }
}
