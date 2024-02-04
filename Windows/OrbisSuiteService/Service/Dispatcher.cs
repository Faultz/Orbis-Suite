using OrbisLib2.Common.Dispatcher;
using Microsoft.Extensions.Logging;
using H.Pipes;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using H.Pipes.AccessControl;
using Google.Protobuf;

namespace OrbisSuiteService.Service
{
    public class Dispatcher
    {
        private IPipeServer<ForwardPacket> _PipeServer;
        private ILogger _Logger;

        private DBWatcher _DBWatcher = new DBWatcher();
        private TargetWatcher _TargetWatcher;
        private TargetEventListener _TargetEventListener;


        public Dispatcher(ILogger logger)
        {
            _Logger = logger;

            // Set up the named pipe server.
            _PipeServer = new PipeServer<ForwardPacket>("OrbisSuite");

            // Set the pipe security so userland can interact with us.
            var pipeSecurity = new PipeSecurity();
            pipeSecurity.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
            _PipeServer.SetPipeSecurity(pipeSecurity);

            // start the pipe server.
            _PipeServer.StartAsync();

            _PipeServer.ClientConnected += _PipeServer_ClientConnected;

            //Helpers
            _DBWatcher.DBChanged += _DBWatcher_DBChanged;
            _TargetWatcher = new TargetWatcher(this);
            _TargetEventListener = new TargetEventListener(this, _Logger);
        }

        private async void _PipeServer_ClientConnected(object? sender, H.Pipes.Args.ConnectionEventArgs<ForwardPacket> e)
        {
            _Logger.LogInformation($"Client {e.Connection.PipeName} is now connected!");
        }

        private void _DBWatcher_DBChanged()
        {
            PublishEvent(new ForwardPacket(ForwardPacket.PacketType.DBTouched, ""));
        }

        public void PublishEvent(ForwardPacket Packet)
        {
            try
            {
                _Logger.LogInformation($"Publishing Event: {Packet.Type}.");
                _PipeServer.WriteAsync(Packet);
            }
            catch (Exception ex)
            {
                _Logger.LogError($"Failed to publish event {ex.Message}.");
            }
        }
    }
}
