using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;

namespace PSMatrix.WorkerService
{
    public sealed class WorkerService : ServiceBase
    {
        private readonly string python;
        private readonly string config;
        private readonly string logDirectory;
        private Process child;
        private readonly object sync = new object();
        private bool stopping;

        public WorkerService(string serviceName, string python, string config, string logDirectory)
        {
            ServiceName = serviceName;
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
            this.python = python;
            this.config = config;
            this.logDirectory = logDirectory;
        }

        protected override void OnStart(string[] args)
        {
            Directory.CreateDirectory(logDirectory);
            stopping = false;
            StartChild();
        }

        private void StartChild()
        {
            lock (sync)
            {
                if (stopping) return;
                var stamp = DateTime.UtcNow.ToString("yyyyMMdd");
                var stdoutPath = Path.Combine(logDirectory, "worker-" + stamp + ".log");
                var stderrPath = Path.Combine(logDirectory, "worker-error-" + stamp + ".log");
                var info = new ProcessStartInfo();
                info.FileName = python;
                info.Arguments = "-m psmatrix worker serve --config \"" + config.Replace("\"", "\\\"") + "\"";
                info.UseShellExecute = false;
                info.CreateNoWindow = true;
                info.RedirectStandardOutput = true;
                info.RedirectStandardError = true;
                child = new Process();
                child.StartInfo = info;
                child.EnableRaisingEvents = true;
                child.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) {
                    if (e.Data != null) AppendLine(stdoutPath, e.Data);
                };
                child.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) {
                    if (e.Data != null) AppendLine(stderrPath, e.Data);
                };
                child.Exited += delegate(object sender, EventArgs e) {
                    lock (sync) {
                        if (!stopping) {
                            ThreadPool.QueueUserWorkItem(delegate(object state) {
                                Thread.Sleep(5000);
                                try { StartChild(); } catch { }
                            });
                        }
                    }
                };
                if (!child.Start()) throw new InvalidOperationException("Unable to start PSMatrix worker child process.");
                child.BeginOutputReadLine();
                child.BeginErrorReadLine();
            }
        }

        private static void AppendLine(string path, string value)
        {
            try
            {
                lock (typeof(WorkerService))
                {
                    File.AppendAllText(path, DateTime.UtcNow.ToString("o") + " " + value + Environment.NewLine);
                }
            }
            catch { }
        }

        protected override void OnStop()
        {
            StopChild();
        }

        protected override void OnShutdown()
        {
            StopChild();
            base.OnShutdown();
        }

        private void StopChild()
        {
            lock (sync)
            {
                stopping = true;
                if (child == null) return;
                try
                {
                    if (!child.HasExited)
                    {
                        Process.Start(new ProcessStartInfo {
                            FileName = "taskkill.exe",
                            Arguments = "/PID " + child.Id + " /T /F",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }).WaitForExit(30000);
                    }
                }
                catch { }
                try { child.Dispose(); } catch { }
                child = null;
            }
        }

        public static void Main(string[] args)
        {
            string serviceName = null, python = null, config = null, logs = null;
            for (int i = 0; i < args.Length - 1; i += 2)
            {
                if (args[i] == "--service-name") serviceName = args[i + 1];
                else if (args[i] == "--python") python = args[i + 1];
                else if (args[i] == "--config") config = args[i + 1];
                else if (args[i] == "--logs") logs = args[i + 1];
            }
            if (String.IsNullOrEmpty(serviceName) || String.IsNullOrEmpty(python) || String.IsNullOrEmpty(config) || String.IsNullOrEmpty(logs))
                throw new ArgumentException("Missing service host arguments.");
            ServiceBase.Run(new WorkerService(serviceName, python, config, logs));
        }
    }
}
