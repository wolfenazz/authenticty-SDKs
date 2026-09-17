namespace Authenticity
{
    partial class MainApp
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
            this.groupBoxUserInfo = new System.Windows.Forms.GroupBox();
            this.labelHwid = new System.Windows.Forms.Label();
            this.labelRemainingTime = new System.Windows.Forms.Label();
            this.labelLevel = new System.Windows.Forms.Label();
            this.labelExpiry = new System.Windows.Forms.Label();
            this.labelToken = new System.Windows.Forms.Label();
            this.labelIp = new System.Windows.Forms.Label();
            this.labelUsername = new System.Windows.Forms.Label();
            this.groupBoxExamples = new System.Windows.Forms.GroupBox();
            this.buttonLogOut = new System.Windows.Forms.Button();
            this.labelVariableResult = new System.Windows.Forms.Label();
            this.buttonSendLog = new System.Windows.Forms.Button();
            this.buttonGetVariable = new System.Windows.Forms.Button();
            this.buttonCheckSession = new System.Windows.Forms.Button();
            this.buttonDownloadFile = new System.Windows.Forms.Button();
            this.buttonTriggerWebhook = new System.Windows.Forms.Button();
            this.buttonBanMe = new System.Windows.Forms.Button();
            this.buttonChat = new System.Windows.Forms.Button();
            this.buttonExit = new System.Windows.Forms.Button();
            this.labelTitle = new System.Windows.Forms.Label();
            this.labelVariableResult1 = new System.Windows.Forms.Label();
            this.groupBoxUserInfo.SuspendLayout();
            this.groupBoxExamples.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBoxUserInfo
            // 
            this.groupBoxUserInfo.Controls.Add(this.labelHwid);
            this.groupBoxUserInfo.Controls.Add(this.labelRemainingTime);
            this.groupBoxUserInfo.Controls.Add(this.labelLevel);
            this.groupBoxUserInfo.Controls.Add(this.labelExpiry);
            this.groupBoxUserInfo.Controls.Add(this.labelToken);
            this.groupBoxUserInfo.Controls.Add(this.labelIp);
            this.groupBoxUserInfo.Controls.Add(this.labelUsername);
            this.groupBoxUserInfo.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBoxUserInfo.ForeColor = System.Drawing.Color.White;
            this.groupBoxUserInfo.Location = new System.Drawing.Point(26, 75);
            this.groupBoxUserInfo.Name = "groupBoxUserInfo";
            this.groupBoxUserInfo.Size = new System.Drawing.Size(748, 260);
            this.groupBoxUserInfo.TabIndex = 0;
            this.groupBoxUserInfo.TabStop = false;
            this.groupBoxUserInfo.Text = "User Info";
            // 
            // labelHwid
            // 
            this.labelHwid.AutoSize = true;
            this.labelHwid.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelHwid.ForeColor = System.Drawing.Color.Silver;
            this.labelHwid.Location = new System.Drawing.Point(25, 220);
            this.labelHwid.Name = "labelHwid";
            this.labelHwid.Size = new System.Drawing.Size(49, 19);
            this.labelHwid.TabIndex = 6;
            this.labelHwid.Text = "HWID:";
            // 
            // labelRemainingTime
            // 
            this.labelRemainingTime.AutoSize = true;
            this.labelRemainingTime.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelRemainingTime.ForeColor = System.Drawing.Color.DeepSkyBlue;
            this.labelRemainingTime.Location = new System.Drawing.Point(25, 190);
            this.labelRemainingTime.Name = "labelRemainingTime";
            this.labelRemainingTime.Size = new System.Drawing.Size(109, 19);
            this.labelRemainingTime.TabIndex = 5;
            this.labelRemainingTime.Text = "Remaining Time:";
            // 
            // labelLevel
            // 
            this.labelLevel.AutoSize = true;
            this.labelLevel.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelLevel.ForeColor = System.Drawing.Color.Lime;
            this.labelLevel.Location = new System.Drawing.Point(25, 160);
            this.labelLevel.Name = "labelLevel";
            this.labelLevel.Size = new System.Drawing.Size(43, 19);
            this.labelLevel.TabIndex = 4;
            this.labelLevel.Text = "Level:";
            // 
            // labelExpiry
            // 
            this.labelExpiry.AutoSize = true;
            this.labelExpiry.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelExpiry.ForeColor = System.Drawing.Color.LightSalmon;
            this.labelExpiry.Location = new System.Drawing.Point(25, 130);
            this.labelExpiry.Name = "labelExpiry";
            this.labelExpiry.Size = new System.Drawing.Size(48, 19);
            this.labelExpiry.TabIndex = 3;
            this.labelExpiry.Text = "Expiry:";
            // 
            // labelToken
            // 
            this.labelToken.AutoSize = true;
            this.labelToken.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelToken.ForeColor = System.Drawing.Color.Violet;
            this.labelToken.Location = new System.Drawing.Point(25, 100);
            this.labelToken.Name = "labelToken";
            this.labelToken.Size = new System.Drawing.Size(48, 19);
            this.labelToken.TabIndex = 2;
            this.labelToken.Text = "Token:";
            // 
            // labelIp
            // 
            this.labelIp.AutoSize = true;
            this.labelIp.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelIp.ForeColor = System.Drawing.Color.Gold;
            this.labelIp.Location = new System.Drawing.Point(25, 70);
            this.labelIp.Name = "labelIp";
            this.labelIp.Size = new System.Drawing.Size(24, 19);
            this.labelIp.TabIndex = 1;
            this.labelIp.Text = "IP:";
            // 
            // labelUsername
            // 
            this.labelUsername.AutoSize = true;
            this.labelUsername.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelUsername.ForeColor = System.Drawing.Color.Cyan;
            this.labelUsername.Location = new System.Drawing.Point(25, 40);
            this.labelUsername.Name = "labelUsername";
            this.labelUsername.Size = new System.Drawing.Size(74, 19);
            this.labelUsername.TabIndex = 0;
            this.labelUsername.Text = "Username:";
            // 
            // groupBoxExamples
            // 
            this.groupBoxExamples.Controls.Add(this.buttonLogOut);
            this.groupBoxExamples.Controls.Add(this.labelVariableResult);
            this.groupBoxExamples.Controls.Add(this.buttonSendLog);
            this.groupBoxExamples.Controls.Add(this.buttonGetVariable);
            this.groupBoxExamples.Controls.Add(this.buttonCheckSession);
            this.groupBoxExamples.Controls.Add(this.buttonDownloadFile);
            this.groupBoxExamples.Controls.Add(this.buttonTriggerWebhook);
            this.groupBoxExamples.Controls.Add(this.buttonBanMe);
            this.groupBoxExamples.Controls.Add(this.buttonChat);
            this.groupBoxExamples.Font = new System.Drawing.Font("Segoe UI", 12F, System.Drawing.FontStyle.Bold);
            this.groupBoxExamples.ForeColor = System.Drawing.Color.White;
            this.groupBoxExamples.Location = new System.Drawing.Point(28, 353);
            this.groupBoxExamples.Name = "groupBoxExamples";
            this.groupBoxExamples.Size = new System.Drawing.Size(748, 120);
            this.groupBoxExamples.TabIndex = 1;
            this.groupBoxExamples.TabStop = false;
            this.groupBoxExamples.Text = "Examples";
            // 
            // buttonLogOut
            // 
            this.buttonLogOut.BackColor = System.Drawing.Color.OrangeRed;
            this.buttonLogOut.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonLogOut.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonLogOut.ForeColor = System.Drawing.Color.White;
            this.buttonLogOut.Location = new System.Drawing.Point(525, 30);
            this.buttonLogOut.Name = "buttonLogOut";
            this.buttonLogOut.Size = new System.Drawing.Size(150, 35);
            this.buttonLogOut.TabIndex = 8;
            this.buttonLogOut.Text = "LogOut";
            this.buttonLogOut.UseVisualStyleBackColor = false;
            this.buttonLogOut.Click += new System.EventHandler(this.buttonLogOut_Click);
            // 
            // labelVariableResult
            // 
            this.labelVariableResult.AutoSize = true;
            this.labelVariableResult.Font = new System.Drawing.Font("Segoe UI", 10F);
            this.labelVariableResult.ForeColor = System.Drawing.Color.Yellow;
            this.labelVariableResult.Location = new System.Drawing.Point(360, 40);
            this.labelVariableResult.Name = "labelVariableResult";
            this.labelVariableResult.Size = new System.Drawing.Size(0, 19);
            this.labelVariableResult.TabIndex = 2;
            // 
            // buttonSendLog
            // 
            this.buttonSendLog.BackColor = System.Drawing.Color.SeaGreen;
            this.buttonSendLog.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonSendLog.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonSendLog.ForeColor = System.Drawing.Color.White;
            this.buttonSendLog.Location = new System.Drawing.Point(29, 75);
            this.buttonSendLog.Name = "buttonSendLog";
            this.buttonSendLog.Size = new System.Drawing.Size(150, 35);
            this.buttonSendLog.TabIndex = 1;
            this.buttonSendLog.Text = "Send Log";
            this.buttonSendLog.UseVisualStyleBackColor = false;
            // 
            // buttonGetVariable
            // 
            this.buttonGetVariable.BackColor = System.Drawing.Color.RoyalBlue;
            this.buttonGetVariable.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonGetVariable.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonGetVariable.ForeColor = System.Drawing.Color.White;
            this.buttonGetVariable.Location = new System.Drawing.Point(29, 30);
            this.buttonGetVariable.Name = "buttonGetVariable";
            this.buttonGetVariable.Size = new System.Drawing.Size(150, 35);
            this.buttonGetVariable.TabIndex = 0;
            this.buttonGetVariable.Text = "Get Remote Variable";
            this.buttonGetVariable.UseVisualStyleBackColor = false;
            // 
            // buttonCheckSession
            // 
            this.buttonCheckSession.BackColor = System.Drawing.Color.DarkOrange;
            this.buttonCheckSession.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonCheckSession.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonCheckSession.ForeColor = System.Drawing.Color.White;
            this.buttonCheckSession.Location = new System.Drawing.Point(195, 30);
            this.buttonCheckSession.Name = "buttonCheckSession";
            this.buttonCheckSession.Size = new System.Drawing.Size(150, 35);
            this.buttonCheckSession.TabIndex = 3;
            this.buttonCheckSession.Text = "Check Session";
            this.buttonCheckSession.UseVisualStyleBackColor = false;
            // 
            // buttonDownloadFile
            // 
            this.buttonDownloadFile.BackColor = System.Drawing.Color.BlueViolet;
            this.buttonDownloadFile.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonDownloadFile.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonDownloadFile.ForeColor = System.Drawing.Color.White;
            this.buttonDownloadFile.Location = new System.Drawing.Point(195, 75);
            this.buttonDownloadFile.Name = "buttonDownloadFile";
            this.buttonDownloadFile.Size = new System.Drawing.Size(150, 35);
            this.buttonDownloadFile.TabIndex = 4;
            this.buttonDownloadFile.Text = "Download File";
            this.buttonDownloadFile.UseVisualStyleBackColor = false;
            // 
            // buttonTriggerWebhook
            // 
            this.buttonTriggerWebhook.BackColor = System.Drawing.Color.Teal;
            this.buttonTriggerWebhook.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonTriggerWebhook.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonTriggerWebhook.ForeColor = System.Drawing.Color.White;
            this.buttonTriggerWebhook.Location = new System.Drawing.Point(360, 75);
            this.buttonTriggerWebhook.Name = "buttonTriggerWebhook";
            this.buttonTriggerWebhook.Size = new System.Drawing.Size(150, 35);
            this.buttonTriggerWebhook.TabIndex = 5;
            this.buttonTriggerWebhook.Text = "Trigger Webhook";
            this.buttonTriggerWebhook.UseVisualStyleBackColor = false;
            // 
            // buttonBanMe
            // 
            this.buttonBanMe.BackColor = System.Drawing.Color.Firebrick;
            this.buttonBanMe.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonBanMe.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonBanMe.ForeColor = System.Drawing.Color.White;
            this.buttonBanMe.Location = new System.Drawing.Point(525, 75);
            this.buttonBanMe.Name = "buttonBanMe";
            this.buttonBanMe.Size = new System.Drawing.Size(150, 35);
            this.buttonBanMe.TabIndex = 6;
            this.buttonBanMe.Text = "Ban Me";
            this.buttonBanMe.UseVisualStyleBackColor = false;
            // 
            // buttonChat
            // 
            this.buttonChat.BackColor = System.Drawing.Color.MediumPurple;
            this.buttonChat.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonChat.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Bold);
            this.buttonChat.ForeColor = System.Drawing.Color.White;
            this.buttonChat.Location = new System.Drawing.Point(360, 30);
            this.buttonChat.Name = "buttonChat";
            this.buttonChat.Size = new System.Drawing.Size(150, 35);
            this.buttonChat.TabIndex = 7;
            this.buttonChat.Text = "Open Chat";
            this.buttonChat.UseVisualStyleBackColor = false;
            // 
            // buttonExit
            // 
            this.buttonExit.BackColor = System.Drawing.Color.Crimson;
            this.buttonExit.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.buttonExit.Font = new System.Drawing.Font("Segoe UI", 9.75F, System.Drawing.FontStyle.Bold);
            this.buttonExit.ForeColor = System.Drawing.Color.White;
            this.buttonExit.Location = new System.Drawing.Point(744, 12);
            this.buttonExit.Name = "buttonExit";
            this.buttonExit.Size = new System.Drawing.Size(35, 35);
            this.buttonExit.TabIndex = 2;
            this.buttonExit.Text = "X";
            this.buttonExit.UseVisualStyleBackColor = false;
            // 
            // labelTitle
            // 
            this.labelTitle.AutoSize = true;
            this.labelTitle.Font = new System.Drawing.Font("Segoe UI", 24F, ((System.Drawing.FontStyle)((System.Drawing.FontStyle.Bold | System.Drawing.FontStyle.Italic))), System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.labelTitle.ForeColor = System.Drawing.Color.DeepPink;
            this.labelTitle.Location = new System.Drawing.Point(20, 20);
            this.labelTitle.Name = "labelTitle";
            this.labelTitle.Size = new System.Drawing.Size(166, 45);
            this.labelTitle.TabIndex = 3;
            this.labelTitle.Text = "Main App";
            // 
            // labelVariableResult1
            // 
            this.labelVariableResult1.AutoSize = true;
            this.labelVariableResult1.ForeColor = System.Drawing.Color.Yellow;
            this.labelVariableResult1.Location = new System.Drawing.Point(329, 342);
            this.labelVariableResult1.Name = "labelVariableResult1";
            this.labelVariableResult1.Size = new System.Drawing.Size(0, 13);
            this.labelVariableResult1.TabIndex = 4;
            // 
            // MainApp
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(25)))), ((int)(((byte)(25)))), ((int)(((byte)(35)))));
            this.ClientSize = new System.Drawing.Size(800, 500);
            this.Controls.Add(this.labelVariableResult1);
            this.Controls.Add(this.labelTitle);
            this.Controls.Add(this.buttonExit);
            this.Controls.Add(this.groupBoxExamples);
            this.Controls.Add(this.groupBoxUserInfo);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Name = "MainApp";
            this.Text = "MainApp";
            this.Load += new System.EventHandler(this.MainApp_Load);
            this.groupBoxUserInfo.ResumeLayout(false);
            this.groupBoxUserInfo.PerformLayout();
            this.groupBoxExamples.ResumeLayout(false);
            this.groupBoxExamples.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBoxUserInfo;
        private System.Windows.Forms.Label labelUsername;
        private System.Windows.Forms.Label labelIp;
        private System.Windows.Forms.Label labelToken;
        private System.Windows.Forms.Label labelExpiry;
        private System.Windows.Forms.Label labelLevel;
        private System.Windows.Forms.Label labelRemainingTime;
        private System.Windows.Forms.Label labelHwid;
        private System.Windows.Forms.GroupBox groupBoxExamples;
        private System.Windows.Forms.Button buttonGetVariable;
        private System.Windows.Forms.Button buttonSendLog;
        private System.Windows.Forms.Button buttonCheckSession;
        private System.Windows.Forms.Button buttonDownloadFile;
        private System.Windows.Forms.Button buttonTriggerWebhook;
        private System.Windows.Forms.Button buttonBanMe;
        private System.Windows.Forms.Button buttonChat;
        private System.Windows.Forms.Label labelVariableResult;
        private System.Windows.Forms.Button buttonExit;
        private System.Windows.Forms.Label labelTitle;
        private System.Windows.Forms.Button buttonLogOut;
        private System.Windows.Forms.Label labelVariableResult1;
    }
}