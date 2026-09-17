using System;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Authenticity
{
    public partial class Login : Form
    {
        // Configure the sample through environment variables; no application
        // credentials or production URL are shipped in the repository.
        private static readonly string OWNER_ID = Environment.GetEnvironmentVariable("AUTH_OWNER_ID") ?? "";
        private static readonly string APP_ID = Environment.GetEnvironmentVariable("AUTH_APP_ID") ?? "";
        private static readonly string API_URL = Environment.GetEnvironmentVariable("AUTH_API_URL") ?? "";
        private static readonly string VERSION = Environment.GetEnvironmentVariable("AUTH_VERSION") ?? "1.0.0";

        private Authenticity client;
        private Point dragOffset;
        private bool isDragging = false;
        public static bool isLoggingOut = false;

        public Login()
        {
            InitializeComponent();
            InitializeEventHandlers();
            
            // Initialize the SDK client
            client = new Authenticity(OWNER_ID, APP_ID, API_URL, VERSION);
            

        }

        private void InitializeEventHandlers()
        {
            // Login button (username/password)
            buttonLoginForUserAndPassword.Click += BtnLoginCredentials_Click;
            
            // Login button (license)
            buttonLoginWithLicense.Click += BtnLoginLicense_Click;
            
            // Close button
            buttonExit.Click += (s, e) => Application.Exit();
            
            // Minimize button
            buttonMinimaize.Click += (s, e) => this.WindowState = FormWindowState.Minimized;
            
            // Register link
            linkLabelRegister.LinkClicked += LinkRegister_Click;
            
            // Enable form dragging from anywhere
            this.MouseDown += Form_MouseDown;
            this.MouseMove += Form_MouseMove;
            this.MouseUp += Form_MouseUp;
            labelAuthanticity.MouseDown += Form_MouseDown;
            labelAuthanticity.MouseMove += Form_MouseMove;
            labelAuthanticity.MouseUp += Form_MouseUp;
        }

        private async void Login_Load(object sender, EventArgs e)
        {
            // Check the dashboard version before attempting auto-login.
            UpdateInfo update = await Task.Run(() => client.CheckForUpdate());
            if (update != null && update.UpdateRequired)
            {
                string message = "This application must be updated to version " + update.CurrentVersion + ".";
                if (!string.IsNullOrEmpty(update.UpdateLink))
                {
                    try
                    {
                        System.Diagnostics.Process.Start(update.UpdateLink);
                        message += " The download page has been opened.";
                    }
                    catch
                    {
                        message += " Download: " + update.UpdateLink;
                    }
                }
                MessageBox.Show(message, "Update required", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Application.Exit();
                return;
            }

            // Check for saved credentials
            SavedCredentials savedCreds = Authenticity.LoadCredentials();
            
            if (savedCreds.IsValid)
            {
                this.Enabled = false;
                this.Cursor = Cursors.WaitCursor;
                
                bool success = false;
                
                try
                {
                    if (savedCreds.LoginType == 1)
                    {
                        // License key login
                        client.SetLicenseKey(savedCreds.LicenseKey);
                        success = await Task.Run(() => client.Login());
                    }
                    else if (savedCreds.LoginType == 2)
                    {
                        // Username/password login
                        success = await Task.Run(() => client.LoginWithCredentials(savedCreds.Username, savedCreds.Password));
                    }
                    
                    if (success)
                    {
                        OpenMainApp();
                        return;
                    }
                    else
                    {
                        // Auto-login failed, clear credentials
                        Authenticity.DeleteCredentials();
                    }
                }
                catch
                {
                    Authenticity.DeleteCredentials();
                }
                finally
                {
                    this.Enabled = true;
                    this.Cursor = Cursors.Default;
                }
            }
        }

        private async void BtnLoginCredentials_Click(object sender, EventArgs e)
        {
            string username = TextBoxUserName.Text.Trim();  // Username field
            string password = TextBoxPassword.Text.Trim();  // Password field
            
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Please enter both username and password.", "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            
            SetLoading(true, buttonLoginForUserAndPassword);
            
            try
            {
                bool success = await Task.Run(() => client.LoginWithCredentials(username, password));
                
                if (success)
                {
                    // Save credentials for auto-login
                    Authenticity.SaveCredentials(2, "", username, password);
                    OpenMainApp();
                }
                else
                {
                    string error = client.GetLastError();
                    string updateLink = client.GetUpdateLink();
                    
                    if (error.ToLower().Contains("banned"))
                    {
                        MessageBox.Show("Access Denied: " + error, "Banned",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else if (error.ToLower().Contains("disabled"))
                    {
                        MessageBox.Show("Access Denied: " + error, "App Disabled",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else if (error.ToLower().Contains("update required"))
                    {
                        if (!string.IsNullOrEmpty(updateLink))
                        {
                            try
                            {
                                System.Diagnostics.Process.Start(updateLink);
                            }
                            catch (Exception ex)
                            {
                                MessageBox.Show($"Failed to open update link: {ex.Message}", "Error",
                                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            Application.Exit();
                        }
                        else
                        {
                            MessageBox.Show("Authentication failed: " + error, "Login Failed",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    else
                    {
                        MessageBox.Show("Authentication failed: " + (string.IsNullOrEmpty(error) ?
                            "Check your inputs or internet connection." : error),
                            "Login Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Login Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetLoading(false, buttonLoginForUserAndPassword);
            }
        }

        private async void BtnLoginLicense_Click(object sender, EventArgs e)
        {
            string licenseKey = textBoxLicenseKey.Text.Trim();  // License key field
            
            if (string.IsNullOrEmpty(licenseKey))
            {
                MessageBox.Show("Please enter a license key.", "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            
            SetLoading(true, buttonLoginWithLicense);
            
            try
            {
                client.SetLicenseKey(licenseKey);
                bool success = await Task.Run(() => client.Login());
                
                if (success)
                {
                    // Save credentials for auto-login
                    Authenticity.SaveCredentials(1, licenseKey, "", "");
                    OpenMainApp();
                }
                else
                {
                    string error = client.GetLastError();
                    string updateLink = client.GetUpdateLink();
                    
                    if (error.ToLower().Contains("banned"))
                    {
                        MessageBox.Show("Access Denied: " + error, "Banned",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else if (error.ToLower().Contains("disabled"))
                    {
                        MessageBox.Show("Access Denied: " + error, "App Disabled",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else if (error.ToLower().Contains("update required"))
                    {
                        if (!string.IsNullOrEmpty(updateLink))
                        {
                            try
                            {
                                System.Diagnostics.Process.Start(updateLink);
                            }
                            catch (Exception ex)
                            {
                                MessageBox.Show($"Failed to open update link: {ex.Message}", "Error",
                                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }
                            Application.Exit();
                        }
                        else
                        {
                            MessageBox.Show("Authentication failed: " + error, "Login Failed",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    else
                    {
                        MessageBox.Show("Authentication failed: " + (string.IsNullOrEmpty(error) ?
                            "Check your license key or internet connection." : error),
                            "Login Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error: " + ex.Message, "Login Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetLoading(false, buttonLoginWithLicense);
            }
        }

        private void LinkRegister_Click(object sender, LinkLabelLinkClickedEventArgs e)
        {
            this.Hide();
            Register registerForm = new Register(OWNER_ID, APP_ID, API_URL, VERSION);
            registerForm.ShowDialog();
            this.Show();
        }

        private void OpenMainApp()
        {
            this.Hide();
            MainApp mainApp = new MainApp(client);
            mainApp.FormClosed += (s, args) =>
            {
                if (!isLoggingOut)
                {
                    Application.Exit();
                }
                else
                {
                    isLoggingOut = false;
                }
            };
            mainApp.Show();
        }

        private void SetLoading(bool loading, Button button)
        {
            this.Enabled = !loading;
            this.Cursor = loading ? Cursors.WaitCursor : Cursors.Default;
            button.Text = loading ? "Loading..." : button.Tag?.ToString() ?? button.Text;
            
            if (!loading && button.Tag == null)
            {
                if (button == buttonLoginForUserAndPassword)
                    button.Text = "Login ( User - password )";
                else if (button == buttonLoginWithLicense)
                    button.Text = "Login ( License )";
            }
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
    }
}
