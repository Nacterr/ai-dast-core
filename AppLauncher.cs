using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace AiDastAppLauncher
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string pythonwExe = Path.Combine(baseDir, ".venv", "Scripts", "pythonw.exe");
            if (!File.Exists(pythonwExe))
            {
                pythonwExe = Path.Combine(baseDir, ".venv", "Scripts", "python.exe");
                if (!File.Exists(pythonwExe))
                {
                    pythonwExe = "pythonw.exe";
                }
            }

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = pythonwExe;
            psi.Arguments = "-m app.desktop";
            psi.WorkingDirectory = baseDir;
            psi.UseShellExecute = false;

            try
            {
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Không thể khởi động ứng dụng AI DAST Desktop:\n" + ex.Message,
                    "Lỗi",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }
    }
}
