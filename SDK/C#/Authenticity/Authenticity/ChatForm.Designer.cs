namespace Authenticity
{
    partial class ChatForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.listBoxChannels = new System.Windows.Forms.ListBox();
            this.richTextBoxMessages = new System.Windows.Forms.RichTextBox();
            this.textBoxInput = new System.Windows.Forms.TextBox();
            this.buttonSend = new System.Windows.Forms.Button();
            this.labelChannels = new System.Windows.Forms.Label();
            this.labelChat = new System.Windows.Forms.Label();
            this.timerRefresh = new System.Windows.Forms.Timer(this.components);
            this.buttonClose = new System.Windows.Forms.Button();
            this.buttonLogOut = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // listBoxChannels
            // 
            this.listBoxChannels.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(35)))), ((int)(((byte)(35)))), ((int)(((byte)(45)))));
            this.listBoxChannels.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.listBoxChannels.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.listBoxChannels.ForeColor = System.Drawing.Color.White;
            this.listBoxChannels.FormattingEnabled = true;
            this.listBoxChannels.ItemHeight = 17;
            this.listBoxChannels.Location = new System.Drawing.Point(20, 50);
            this.listBoxChannels.Name = "listBoxChannels";
            this.listBoxChannels.Size = new System.Drawing.Size(180, 374);
            this.listBoxChannels.TabIndex = 0;
            this.listBoxChannels.SelectedIndexChanged += new System.EventHandler(this.ListBoxChannels_SelectedIndexChanged);
            // 
            // richTextBoxMessages
            // 
            this.richTextBoxMessages.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(35)))), ((int)(((byte)(35)))), ((int)(((byte)(45)))));
            this.richTextBoxMessages.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.richTextBoxMessages.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.richTextBoxMessages.ForeColor = System.Drawing.Color.White;
            this.richTextBoxMessages.Location = new System.Drawing.Point(220, 50);
            this.richTextBoxMessages.Name = "richTextBoxMessages";
            this.richTextBoxMessages.ReadOnly = true;
            this.richTextBoxMessages.Size = new System.Drawing.Size(560, 320);
            this.richTextBoxMessages.TabIndex = 1;
            this.richTextBoxMessages.Text = "";
            // 
            // textBoxInput
            // 
            this.textBoxInput.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(45)))), ((int)(((byte)(45)))), ((int)(((byte)(55)))));
            this.textBoxInput.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.textBoxInput.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.textBoxInput.ForeColor = System.Drawing.Color.White;
            this.textBoxInput.Location = new System.Drawing.Point(220, 390);
            this.textBoxInput.Name = "textBoxInput";
            this.textBoxInput.Size = new System.Drawing.Size(460, 25);
            this.textBoxInput.TabIndex = 2;
            this.textBoxInput.KeyDown += new System.Windows.Forms.KeyEventHandler(this.TextBoxInput_KeyDown);
            // 
            // buttonSend
            // 
            this.buttonSend.BackColor = System.Drawing.Color.DodgerBlue;
            this.buttonSend.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonSend.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonSend.ForeColor = System.Drawing.Color.White;
            this.buttonSend.Location = new System.Drawing.Point(690, 388);
            this.buttonSend.Name = "buttonSend";
            this.buttonSend.Size = new System.Drawing.Size(90, 29);
            this.buttonSend.TabIndex = 3;
            this.buttonSend.Text = "Send";
            this.buttonSend.UseVisualStyleBackColor = false;
            this.buttonSend.Click += new System.EventHandler(this.ButtonSend_Click);
            // 
            // labelChannels
            // 
            this.labelChannels.AutoSize = true;
            this.labelChannels.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold);
            this.labelChannels.ForeColor = System.Drawing.Color.White;
            this.labelChannels.Location = new System.Drawing.Point(20, 20);
            this.labelChannels.Name = "labelChannels";
            this.labelChannels.Size = new System.Drawing.Size(79, 21);
            this.labelChannels.TabIndex = 4;
            this.labelChannels.Text = "Channels";
            // 
            // labelChat
            // 
            this.labelChat.AutoSize = true;
            this.labelChat.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold);
            this.labelChat.ForeColor = System.Drawing.Color.White;
            this.labelChat.Location = new System.Drawing.Point(220, 20);
            this.labelChat.Name = "labelChat";
            this.labelChat.Size = new System.Drawing.Size(45, 21);
            this.labelChat.TabIndex = 5;
            this.labelChat.Text = "Chat";
            // 
            // timerRefresh
            // 
            this.timerRefresh.Interval = 2000;
            this.timerRefresh.Tick += new System.EventHandler(this.TimerRefresh_Tick);
            // 
            // buttonClose
            // 
            this.buttonClose.BackColor = System.Drawing.Color.Crimson;
            this.buttonClose.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonClose.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonClose.ForeColor = System.Drawing.Color.White;
            this.buttonClose.Location = new System.Drawing.Point(755, 12);
            this.buttonClose.Name = "buttonClose";
            this.buttonClose.Size = new System.Drawing.Size(25, 25);
            this.buttonClose.TabIndex = 6;
            this.buttonClose.Text = "X";
            this.buttonClose.UseVisualStyleBackColor = false;
            this.buttonClose.Click += new System.EventHandler(this.ButtonClose_Click);
            //
            // buttonLogOut
            //
            this.buttonLogOut.BackColor = System.Drawing.Color.OrangeRed;
            this.buttonLogOut.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonLogOut.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonLogOut.ForeColor = System.Drawing.Color.White;
            this.buttonLogOut.Location = new System.Drawing.Point(690, 12);
            this.buttonLogOut.Name = "buttonLogOut";
            this.buttonLogOut.Size = new System.Drawing.Size(60, 25);
            this.buttonLogOut.TabIndex = 7;
            this.buttonLogOut.Text = "LogOut";
            this.buttonLogOut.UseVisualStyleBackColor = false;
            this.buttonLogOut.Click += new System.EventHandler(this.ButtonLogOut_Click);
            //
            // ChatForm
            //
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(25)))), ((int)(((byte)(25)))), ((int)(((byte)(35)))));
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.buttonLogOut);
            this.Controls.Add(this.buttonClose);
            this.Controls.Add(this.labelChat);
            this.Controls.Add(this.labelChannels);
            this.Controls.Add(this.buttonSend);
            this.Controls.Add(this.textBoxInput);
            this.Controls.Add(this.richTextBoxMessages);
            this.Controls.Add(this.listBoxChannels);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Name = "ChatForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Chat";
            this.Load += new System.EventHandler(this.ChatForm_Load);
            this.MouseDown += new System.Windows.Forms.MouseEventHandler(this.Form_MouseDown);
            this.MouseMove += new System.Windows.Forms.MouseEventHandler(this.Form_MouseMove);
            this.MouseUp += new System.Windows.Forms.MouseEventHandler(this.Form_MouseUp);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ListBox listBoxChannels;
        private System.Windows.Forms.RichTextBox richTextBoxMessages;
        private System.Windows.Forms.TextBox textBoxInput;
        private System.Windows.Forms.Button buttonSend;
        private System.Windows.Forms.Label labelChannels;
        private System.Windows.Forms.Label labelChat;
        private System.Windows.Forms.Timer timerRefresh;
        private System.Windows.Forms.Button buttonClose;
        private System.Windows.Forms.Button buttonLogOut;
    }
}
