using System;
using System.Drawing;
using System.Windows.Forms;

namespace Authenticity
{
    public partial class MainApp : Form
    {
        private Authenticity client;
        private Point dragOffset;
        private bool isDragging = false;
        private Timer heartbeatTimer;

        public MainApp(Authenticity client)
        {
            InitializeComponent();
            this.client = client;
            
            InitializeEventHandlers();
            InitializeHeartbeat();
            this.Load += MainApp_Load;
        }

        private void InitializeHeartbeat()
        {
            heartbeatTimer = new Timer();
            heartbeatTimer.Interval = 30000; // 30 seconds
            heartbeatTimer.Tick += HeartbeatTimer_Tick;
            heartbeatTimer.Start();
        }

        private void HeartbeatTimer_Tick(object sender, EventArgs e)
        {
            if (!client.CheckSession())
            {
                heartbeatTimer.Stop();
                MessageBox.Show("Session expired or invalid: " + client.GetLastError() + "\n\nThe application will now close.", 
                    "Session Invalid", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        private void InitializeEventHandlers()
        {
            // Exit button
            buttonExit.Click += (s, e) => Application.Exit();

            // Example buttons
            buttonGetVariable.Click += ButtonGetVariable_Click;
            buttonSendLog.Click += ButtonSendLog_Click;
            buttonCheckSession.Click += ButtonCheckSession_Click;
            buttonDownloadFile.Click += ButtonDownloadFile_Click;
            buttonTriggerWebhook.Click += ButtonTriggerWebhook_Click;
            buttonBanMe.Click += ButtonBanMe_Click;
            buttonChat.Click += ButtonChat_Click;
           
            

            // Form dragging
            this.MouseDown += Form_MouseDown;
            this.MouseMove += Form_MouseMove;
            this.MouseUp += Form_MouseUp;
            labelTitle.MouseDown += Form_MouseDown;
            labelTitle.MouseMove += Form_MouseMove;
            labelTitle.MouseUp += Form_MouseUp;
        }

        private void MainApp_Load(object sender, EventArgs e)
        {
            Session session = client.GetSession();
            
            if (session.IsValid)
            {
                labelUsername.Text = "Username: " + session.Username;
                labelIp.Text = "IP: " + session.IP;
                labelToken.Text = "Token: " + (session.Token.Length > 20 ? session.Token.Substring(0, 20) + "..." : session.Token);
                labelExpiry.Text = "Expiry: " + session.Expiry;
                labelLevel.Text = "Level: " + session.Level;
                labelRemainingTime.Text = "Remaining Time: " + client.GetRemainingTime();
                labelHwid.Text = "HWID: " + session.Hwid;
            }
        }

        private void ButtonGetVariable_Click(object sender, EventArgs e)
        {
            // Example: Get a remote variable named "welcome_msg"
            // You should create this variable in your dashboard first
            string value = client.GetVariable("welcome_msg");
            
            if (!string.IsNullOrEmpty(value))
            {
                labelVariableResult1.Text = "Value: " + value;
                labelVariableResult1.ForeColor = Color.Yellow;
            }
            else
            {
                labelVariableResult1.Text = "Variable not found or empty (You should create this variable in your dashboard first , the example name of the variable is : (welcome_msg) ";
                labelVariableResult1.ForeColor = Color.Red;
            }
        }

        private void ButtonSendLog_Click(object sender, EventArgs e)
        {
            // Example: Send a log to the dashboard
            client.Log("User clicked the Send Log button", "info");
            MessageBox.Show("Log sent to dashboard!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ButtonCheckSession_Click(object sender, EventArgs e)
        {
            // Example: Check if session is valid
            bool isValid = client.CheckSession();
            if (isValid)
            {
                MessageBox.Show("Session is valid!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Session is invalid: " + client.GetLastError(), "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        private void ButtonDownloadFile_Click(object sender, EventArgs e)
        {
            // Use the proper API endpoint for downloading files
            // This will trigger a direct download link , you must intialize it in your dashboard first
            if (!client.DownloadFileDirect("test_file"))
            {
                MessageBox.Show("Failed to download file: " + client.GetLastError(), "Download Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ButtonTriggerWebhook_Click(object sender, EventArgs e)
        {
            // Example: Trigger a webhook (placeholder "test_webhook")
            // You should create a webhook in your dashboard first
            bool success = client.TriggerWebhook("test_webhook", "{\"message\":\"Hello from C# SDK\"}");
            if (success)
            {
                MessageBox.Show("Webhook triggered successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
            }
        }

        private void ButtonBanMe_Click(object sender, EventArgs e)
        {
            DialogResult result = MessageBox.Show("Are you sure you want to ban yourself?", "Confirm Ban", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result == DialogResult.Yes)
            {
                client.Ban("User requested self-ban");
                MessageBox.Show("You have been banned!");
                Application.Exit();
            }
        }

        private void ButtonChat_Click(object sender, EventArgs e)
        {
            ChatForm chatForm = new ChatForm(client);
            chatForm.Show();
        }

        #region Form Dragging

        private void Form_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                isDragging = true;
                dragOffset = new Point(e.X, e.Y);
            }
        }

        private void Form_MouseMove(object sender, MouseEventArgs e)
        {
            if (isDragging)
            {
                Point currentScreenPos = PointToScreen(e.Location);
                Location = new Point(currentScreenPos.X - dragOffset.X, currentScreenPos.Y - dragOffset.Y);
            }
        }

        private void Form_MouseUp(object sender, MouseEventArgs e)
        {
            isDragging = false;
        }

        #endregion

        private void buttonLogOut_Click(object sender, EventArgs e)
        {
            // Clear saved credentials
            Authenticity.DeleteCredentials();
            
            // Set the logout flag to prevent application exit
            Login.isLoggingOut = true;
            
            // Close any open ChatForm windows
            foreach (Form form in Application.OpenForms)
            {
                if (form is ChatForm)
                {
                    form.Close();
                }
            }
            
            // Show the Login form
            Login loginForm = new Login();
            loginForm.Show();
            
            // Close this form
            this.Close();
        }

      
    }
}
