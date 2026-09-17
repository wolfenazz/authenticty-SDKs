using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Authenticity
{
    public partial class Register : Form
    {
        private Authenticity client;
        private string ownerId;
        private string appId;
        private string apiUrl;
        private string version;
        private Point dragOffset;
        private bool isDragging = false;

        // Parameterless constructor for designer support
        public Register()
        {
            InitializeComponent();
        }

        public Register(string ownerId, string appId, string apiUrl, string version)
        {
            this.ownerId = ownerId;
            this.appId = appId;
            this.apiUrl = apiUrl;
            this.version = version;
            
            client = new Authenticity(ownerId, appId, apiUrl, version);
            InitializeComponent();
            SetupEventHandlers();
        }

        private void SetupEventHandlers()
        {
            // Register button
            buttonRegister.Click += BtnRegister_Click;
            
            // Back to login button
            buttonBackToLogin.Click += (s, e) => this.Close();
            
            // Close button
            buttonExsit.Click += (s, e) => this.Close();
            
            // Minimize button
            buttonMinimaiz.Click += (s, e) => this.WindowState = FormWindowState.Minimized;

            // Set password character for password fields
            textBoxPassword.UseSystemPasswordChar = true;
            textBoxReWritePassword.UseSystemPasswordChar = true;

            // Enable form dragging
            this.MouseDown += Form_MouseDown;
            this.MouseMove += Form_MouseMove;
            this.MouseUp += Form_MouseUp;
            labelRegister.MouseDown += Form_MouseDown;
            labelRegister.MouseMove += Form_MouseMove;
            labelRegister.MouseUp += Form_MouseUp;
        }

        private async void BtnRegister_Click(object sender, EventArgs e)
        {
            string username = textBoxUserName.Text.Trim();
            string password = textBoxPassword.Text;
            string confirmPassword = textBoxReWritePassword.Text;
            string licenseKey = textBoxLicesne.Text.Trim();

            // Validation
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password) || 
                string.IsNullOrEmpty(confirmPassword) || string.IsNullOrEmpty(licenseKey))
            {
                UpdateStatus("Please fill in all fields.", Color.Red);
                MessageBox.Show("Please fill in all fields.", "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (password != confirmPassword)
            {
                UpdateStatus("Passwords do not match.", Color.Red);
                MessageBox.Show("Passwords do not match.", "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (password.Length < 4)
            {
                UpdateStatus("Password too short.", Color.Red);
                MessageBox.Show("Password must be at least 4 characters.", "Validation Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            SetLoading(true);
            UpdateStatus("Registering...", Color.Yellow);

            try
            {
                // Ensure client is initialized
                if (client == null)
                {
                    client = new Authenticity(ownerId, appId, apiUrl, version);
                }

                bool success = await Task.Run(() => client.Register(username, password, licenseKey));

                if (success)
                {
                    UpdateStatus("Registration successful!", Color.LimeGreen);
                    MessageBox.Show("Registration successful! You can now login with your credentials.", 
                        "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    this.Close();
                }
                else
                {
                    string error = client.GetLastError();
                    UpdateStatus("Registration failed: " + error, Color.Red);
                    MessageBox.Show("Registration failed: " + (string.IsNullOrEmpty(error) ? 
                        "Unknown error" : error), "Registration Failed", 
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch (Exception ex)
            {
                UpdateStatus("Error: " + ex.Message, Color.Red);
                MessageBox.Show("Error: " + ex.Message, "Registration Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetLoading(false);
            }
        }

        private void SetLoading(bool loading)
        {
            this.Enabled = !loading;
            this.Cursor = loading ? Cursors.WaitCursor : Cursors.Default;
            buttonRegister.Text = loading ? "Registering..." : "Register ";
        }

        private void UpdateStatus(string message, Color color)
        {
            labelStates.Text = "Status: " + message;
            labelStates.ForeColor = color;
        }

        private void Register_Load(object sender, EventArgs e)
        {
            // Set initial status
            labelStates.Text = "Status: Ready";
            labelStates.ForeColor = Color.White;
            
            this.StartPosition = FormStartPosition.CenterParent;
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
