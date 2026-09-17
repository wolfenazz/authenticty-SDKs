using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace Authenticity
{
    public partial class ChatForm : Form
    {
        private Authenticity client;
        private List<ChatChannel> channels;
        private string currentChannelId;
        private bool isDragging = false;
        private Point startPoint = new Point(0, 0);

        public ChatForm(Authenticity client)
        {
            InitializeComponent();
            this.client = client;
        }

        private void ChatForm_Load(object sender, EventArgs e)
        {
            LoadChannels();
            timerRefresh.Start();
        }

        private void LoadChannels()
        {
            channels = client.GetChannels();
            listBoxChannels.Items.Clear();
            foreach (var channel in channels)
            {
                listBoxChannels.Items.Add(channel.Name);
            }

            if (listBoxChannels.Items.Count > 0)
            {
                listBoxChannels.SelectedIndex = 0;
            }
            else
            {
                string error = client.GetLastError();
                if (!string.IsNullOrEmpty(error))
                {
                    MessageBox.Show("Failed to load channels: " + error, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void ListBoxChannels_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (listBoxChannels.SelectedIndex == -1) return;

            var selectedChannel = channels[listBoxChannels.SelectedIndex];
            currentChannelId = selectedChannel.Id;
            LoadMessages();
        }

        private void LoadMessages()
        {
            if (string.IsNullOrEmpty(currentChannelId)) return;

            var messages = client.GetMessages(currentChannelId);
            
            // Simple check to avoid flickering if nothing changed (basic implementation)
            // In a real app, we'd compare IDs or timestamps
            
            string currentText = "";
            foreach (var msg in messages)
            {
                // Format timestamp
                DateTime time;
                string timeStr = msg.TimeSent;
                if (DateTime.TryParse(msg.TimeSent, out time))
                {
                    timeStr = time.ToString("HH:mm");
                }

                currentText += $"[{timeStr}] {msg.Sender}: {msg.Content}\n";
            }

            if (richTextBoxMessages.Text != currentText)
            {
                richTextBoxMessages.Text = currentText;
                richTextBoxMessages.SelectionStart = richTextBoxMessages.Text.Length;
                richTextBoxMessages.ScrollToCaret();
            }
        }

        private void ButtonSend_Click(object sender, EventArgs e)
        {
            SendMessage();
        }

        private void TextBoxInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                SendMessage();
                e.SuppressKeyPress = true; // Prevent newline in textbox
            }
        }

        private void SendMessage()
        {
            if (string.IsNullOrEmpty(currentChannelId) || string.IsNullOrWhiteSpace(textBoxInput.Text)) return;

            string content = textBoxInput.Text.Trim();
            bool success = client.SendMessage(currentChannelId, content);

            if (success)
            {
                textBoxInput.Clear();
                LoadMessages(); // Instant refresh
            }
            else
            {
                MessageBox.Show("Failed to send message. " + client.GetLastError());
            }
        }

        private void TimerRefresh_Tick(object sender, EventArgs e)
        {
            LoadMessages();
        }

        private void ButtonClose_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void ButtonLogOut_Click(object sender, EventArgs e)
        {
            // Clear saved credentials
            Authenticity.DeleteCredentials();
            
            // Set the logout flag to prevent application exit
            Login.isLoggingOut = true;
            
            // Find and close the MainApp form
            foreach (Form form in Application.OpenForms)
            {
                if (form is MainApp)
                {
                    form.Close();
                    break;
                }
            }
            
            // Close this form
            this.Close();
            
            // Show the Login form
            Login loginForm = new Login();
            loginForm.Show();
        }

        // Dragging logic
        private void Form_MouseDown(object sender, MouseEventArgs e)
        {
            isDragging = true;
            startPoint = new Point(e.X, e.Y);
        }

        private void Form_MouseMove(object sender, MouseEventArgs e)
        {
            if (isDragging)
            {
                Point p = PointToScreen(e.Location);
                Location = new Point(p.X - startPoint.X, p.Y - startPoint.Y);
            }
        }

        private void Form_MouseUp(object sender, MouseEventArgs e)
        {
            isDragging = false;
        }
    }
}
