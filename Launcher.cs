using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Windows.Forms;

namespace AiDastLauncher
{
    static class Program
    {
        private static Process backendProcess = null;
        private static NotifyIcon trayIcon = null;
        private static int port = 8093;
        private static string appUrl = string.Format("http://127.0.0.1:{0}", port);

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // Check if backend service is already running on port 8093
            bool backendAlreadyRunning = IsPortOpen("127.0.0.1", port);

            if (!backendAlreadyRunning)
            {
                // Find python executable (in .venv or system)
                string pythonExe = Path.Combine(baseDir, ".venv", "Scripts", "python.exe");
                if (!File.Exists(pythonExe))
                {
                    DirectoryInfo parent = Directory.GetParent(baseDir);
                    string parentDir = parent != null ? parent.FullName : baseDir;
                    string parentPy = Path.Combine(parentDir, ".venv", "Scripts", "python.exe");
                    if (File.Exists(parentPy))
                    {
                        pythonExe = parentPy;
                        baseDir = parentDir;
                    }
                    else
                    {
                        pythonExe = "python.exe";
                    }
                }

                // Start backend serve process in hidden background mode
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = pythonExe;
                psi.Arguments = string.Format(
                    "-m app.main serve --host 127.0.0.1 --port {0} --api-allowed-host \"*\" --api-allowed-port 80 --api-allowed-port 443 --api-allowed-port 8099 --api-allow-private --api-allow-active --api-allow-injection",
                    port
                );
                psi.WorkingDirectory = baseDir;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;

                try
                {
                    backendProcess = Process.Start(psi);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        "Không thể khởi động ai-dast-core backend:\n" + ex.Message + "\n\nĐường dẫn: " + pythonExe,
                        "Lỗi khởi động",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }

                // Ensure child backend process is killed when launcher process exits
                AppDomain.CurrentDomain.ProcessExit += delegate
                {
                    KillBackend();
                };

                // Wait until backend port is listening (up to 12 seconds)
                bool connected = false;
                for (int i = 0; i < 48; i++)
                {
                    Thread.Sleep(250);
                    if (backendProcess.HasExited)
                    {
                        MessageBox.Show(
                            "Dịch vụ ai-dast-core đã dừng bất ngờ (exit code: " + backendProcess.ExitCode + "). Vui lòng kiểm tra môi trường Python.",
                            "Lỗi khởi động",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error
                        );
                        return;
                    }
                    if (IsPortOpen("127.0.0.1", port))
                    {
                        connected = true;
                        break;
                    }
                }

                if (!connected)
                {
                    MessageBox.Show(
                        "Backend AI DAST khởi động chậm hoặc không thể kết nối tới cổng " + port + ".",
                        "Cảnh báo",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning
                    );
                }
            }

            // Immediately open Desktop App window
            LaunchAppWindow(appUrl);

            // Create System Tray Icon (Khay hệ thống góc phải màn hình)
            ContextMenu trayMenu = new ContextMenu();
            trayMenu.MenuItems.Add(new MenuItem("Mở ứng dụng Desktop (Open App)", delegate { LaunchAppWindow(appUrl); }));
            trayMenu.MenuItems.Add(new MenuItem("Mở trên trình duyệt (Browser)", delegate { Process.Start(appUrl); }));
            trayMenu.MenuItems.Add(new MenuItem("Tạo link Online (Cloudflare Tunnel)", delegate { LaunchCloudflareTunnel(); }));
            trayMenu.MenuItems.Add("-");
            trayMenu.MenuItems.Add(new MenuItem("Thoát hoàn toàn (Exit)", delegate { ExitApplication(); }));

            trayIcon = new NotifyIcon();
            trayIcon.Text = "AI DAST Security Core (Port 8093)";
            trayIcon.Icon = SystemIcons.Shield;
            trayIcon.ContextMenu = trayMenu;
            trayIcon.Visible = true;

            // Single click or double click on tray icon opens the App window
            trayIcon.Click += delegate(object sender, EventArgs e)
            {
                MouseEventArgs me = e as MouseEventArgs;
                if (me != null && me.Button == MouseButtons.Left)
                {
                    LaunchAppWindow(appUrl);
                }
            };

            trayIcon.ShowBalloonTip(
                3000,
                "AI DAST Core đã sẵn sàng",
                "Ứng dụng đang chạy trên cổng 8093. Nhấp vào biểu tượng dưới khay để mở lại giao diện bất kỳ lúc nào.",
                ToolTipIcon.Info
            );

            // Keep application message loop running for tray icon
            Application.Run();
        }

        private static void LaunchAppWindow(string url)
        {
            string appBrowser = FindChromiumBrowser();
            if (!string.IsNullOrEmpty(appBrowser))
            {
                ProcessStartInfo appPsi = new ProcessStartInfo();
                appPsi.FileName = appBrowser;
                appPsi.Arguments = string.Format(
                    "--app=\"{0}\" --window-size=1400,900 --no-first-run --no-default-browser-check",
                    url
                );
                appPsi.UseShellExecute = false;

                try
                {
                    Process.Start(appPsi);
                    return;
                }
                catch { }
            }

            // Fallback to default browser
            try
            {
                Process.Start(url);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Không thể mở giao diện: " + ex.Message, "Thông báo");
            }
        }

        private static void LaunchCloudflareTunnel()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string cloudflaredPath = Path.Combine(baseDir, "tools", "cloudflared.exe");
            if (!File.Exists(cloudflaredPath))
            {
                MessageBox.Show("Không tìm thấy tools\\cloudflared.exe. Vui lòng kiểm tra lại thư mục.", "Thông báo");
                return;
            }
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = cloudflaredPath;
                psi.Arguments = "tunnel --url http://127.0.0.1:8093";
                psi.WorkingDirectory = baseDir;
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Không thể khởi động Cloudflare Tunnel: " + ex.Message, "Lỗi");
            }
        }

        private static void ExitApplication()
        {
            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }
            KillBackend();
            Application.Exit();
        }

        private static void KillBackend()
        {
            try
            {
                if (backendProcess != null && !backendProcess.HasExited)
                {
                    backendProcess.Kill();
                }
            }
            catch { }
        }

        private static bool IsPortOpen(string host, int port)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult result = client.BeginConnect(host, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(200);
                    if (success && client.Connected)
                    {
                        client.EndConnect(result);
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private static string FindChromiumBrowser()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            string[] candidatePaths = new string[]
            {
                Path.Combine(progFilesX86, "Microsoft\\Edge\\Application\\msedge.exe"),
                Path.Combine(progFiles, "Microsoft\\Edge\\Application\\msedge.exe"),
                Path.Combine(localAppData, "Microsoft\\Edge\\Application\\msedge.exe"),
                Path.Combine(progFiles, "Google\\Chrome\\Application\\chrome.exe"),
                Path.Combine(progFilesX86, "Google\\Chrome\\Application\\chrome.exe"),
                Path.Combine(localAppData, "Google\\Chrome\\Application\\chrome.exe")
            };

            foreach (string path in candidatePaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
            }

            return null;
        }
    }
}
