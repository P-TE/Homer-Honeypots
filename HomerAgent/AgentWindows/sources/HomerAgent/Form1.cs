using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
using HomerAgent.Object;

namespace HomerAgent
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        // Event onClick
        private void button1_Click(object sender, EventArgs e)
        {
     
            string path = "http://" + txtPath.Text;
            // Call GetCreds : result into creds[]
            string[] creds = GetCreds(path);
            string username = creds[0];
            string password = creds[1];
            string domain = creds[2].TrimEnd();
            // Confirm
            DialogResult dialogResult = MessageBox.Show("Domain : " + domain + "\r\nUsername : " + username + " \r\nPassword : " + password, "Confirmation", MessageBoxButtons.OKCancel);
            if (dialogResult == DialogResult.OK)
            {
                this.Visible = false;
                while (true)
                {
                    // Call CreateProcessWithLogon
                    uint pid = CreateProcessWithLogon(domain, username, password);
                    if (pid != 0)
                    {
                        System.Threading.Thread.Sleep(43200000);
                        try
                        {
                            Process lastProcess = Process.GetProcessById((int)pid);
                            lastProcess.Kill();
                        }
                        catch (Exception)
                        {
                            Debug.WriteLine("GetProcessByID failed");
                        }
                    }
                }
            }
        }


        private uint CreateProcessWithLogon(string domain, string user, string password)
        {
            // Call CreateHoneytokenProcess
            uint pid = CreateProcessHomer.CreateHoneytokenProcess(
                 "C:\\Windows\\System32\\notepad.exe",
                 domain,
                 user,
                 password,
                 CreateProcessHomer.LogonFlags.LOGON_NETCREDENTIALS_ONLY, 
                 CreateProcessHomer.CreationFlags.CREATE_SUSPENDED
                 );
            return pid;

        }
        private  string[] GetCreds(string path)
        {
            string[] creds;
            try
            {
                WebRequest request = WebRequest.Create(path);
                WebResponse response = request.GetResponse();
                Stream dataStream = response.GetResponseStream();
                StreamReader reader = new StreamReader(dataStream);
                string responseFromServer = reader.ReadToEnd();
                reader.Close();
                response.Close();
                creds = responseFromServer.Split('/');
            }
            catch
            {
                MessageBox.Show("Impossible de récuperer le fichier de configuration", "HomerAgent");
                txtPath.Enabled = true;
                creds = new string[] {"NULL","NULL","NULL"};
            }
            return creds;

        }
        private void txtPath_TextChanged(object sender, EventArgs e)
        {

        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }       
}
