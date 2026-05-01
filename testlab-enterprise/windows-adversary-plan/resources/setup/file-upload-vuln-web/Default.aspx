<%@ Page Language="C#" ContentType="text/html" ResponseEncoding="UTF-8" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document Portal - TestLab Corp</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f0f2f5;
            min-height: 100vh;
            color: #1a1a2e;
        }
        header {
            background: #1a1a2e;
            color: white;
            padding: 0 40px;
            height: 56px;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.3);
        }
        header .logo-icon {
            width: 28px; height: 28px;
            background: #4f8ef7;
            border-radius: 6px;
            display: flex; align-items: center; justify-content: center;
            font-weight: 700; font-size: 14px; color: white;
        }
        header .brand { font-size: 15px; font-weight: 600; letter-spacing: 0.2px; }
        header .brand span { color: #4f8ef7; }
        header nav { margin-left: auto; display: flex; gap: 24px; }
        header nav a { color: #a0aec0; font-size: 13px; text-decoration: none; }
        header nav a:hover { color: white; }
        .main { max-width: 860px; margin: 40px auto; padding: 0 20px; display: grid; gap: 24px; }
        .page-title { font-size: 22px; font-weight: 700; color: #1a1a2e; }
        .page-title span { color: #4f8ef7; }
        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        .card-header {
            padding: 16px 24px;
            border-bottom: 1px solid #f0f2f5;
            display: flex; align-items: center; gap: 10px;
        }
        .card-header .icon {
            width: 32px; height: 32px;
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 15px;
        }
        .card-header .icon.blue { background: #ebf3ff; }
        .card-header .icon.gray { background: #f5f5f5; }
        .card-header h2 { font-size: 15px; font-weight: 600; color: #1a1a2e; }
        .card-header p  { font-size: 12px; color: #718096; margin-top: 1px; }
        .card-body { padding: 24px; }
        .drop-zone {
            border: 2px dashed #d1dce8;
            border-radius: 8px;
            padding: 36px 24px;
            text-align: center;
            background: #fafbfc;
            transition: border-color 0.2s, background 0.2s;
            cursor: pointer;
            position: relative;
        }
        .drop-zone:hover { border-color: #4f8ef7; background: #f0f6ff; }
        .drop-zone .dz-icon { font-size: 36px; margin-bottom: 10px; }
        .drop-zone p { font-size: 14px; color: #4a5568; }
        .drop-zone small { font-size: 12px; color: #a0aec0; margin-top: 4px; display: block; }
        .file-input-wrap { margin-top: 16px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .file-input-wrap input[type=file] {
            flex: 1;
            font-size: 13px;
            padding: 8px 12px;
            border: 1px solid #d1dce8;
            border-radius: 6px;
            background: white;
            color: #4a5568;
            min-width: 0;
        }
        .btn-upload {
            background: #4f8ef7;
            color: white;
            border: none;
            padding: 9px 22px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            font-family: inherit;
            white-space: nowrap;
            transition: background 0.15s;
        }
        .btn-upload:hover { background: #3a7de0; }
        .btn-upload:active { background: #2f6bc5; }
        .alert {
            margin-top: 16px;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 13px;
            display: flex; align-items: center; gap: 8px;
        }
        .alert-success { background: #f0fff4; border: 1px solid #9ae6b4; color: #276749; }
        .alert-error   { background: #fff5f5; border: 1px solid #feb2b2; color: #9b2c2c; }
        .file-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .file-table thead tr { background: #f7f8fa; }
        .file-table th {
            text-align: left;
            padding: 10px 14px;
            font-weight: 600;
            color: #718096;
            font-size: 11.5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #edf2f7;
        }
        .file-table td {
            padding: 11px 14px;
            border-bottom: 1px solid #f0f2f5;
            color: #2d3748;
            vertical-align: middle;
        }
        .file-table tr:last-child td { border-bottom: none; }
        .file-table tr:hover td { background: #fafbfc; }
        .file-table a { color: #4f8ef7; text-decoration: none; font-weight: 500; }
        .file-table a:hover { text-decoration: underline; }
        .file-ext {
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            background: #edf2f7;
            color: #4a5568;
            text-transform: uppercase;
        }
        .empty-state { text-align: center; padding: 36px 0; color: #a0aec0; font-size: 13.5px; }
        .empty-state .e-icon { font-size: 32px; margin-bottom: 8px; }
    </style>
</head>
<body>
    <header>
        <div class="logo-icon">TC</div>
        <span class="brand">TestLab <span>Corp</span></span>
        <nav>
            <a href="#">Dashboard</a>
            <a href="#">Documents</a>
            <a href="#">Settings</a>
        </nav>
    </header>

    <div class="main">
        <h1 class="page-title">Document <span>Upload Portal</span></h1>

        <div class="card">
            <div class="card-header">
                <div class="icon blue">&#128228;</div>
                <div>
                    <h2>Upload File</h2>
                    <p>Share documents with your team</p>
                </div>
            </div>
            <div class="card-body">
                <div class="drop-zone">
                    <div class="dz-icon">&#128194;</div>
                    <p>Drag &amp; drop your file here</p>
                    <small>or use the file picker below</small>
                </div>
                <form id="uploadForm" runat="server">
                    <div class="file-input-wrap">
                        <asp:FileUpload ID="FileUpload1" runat="server" />
                        <asp:Button ID="btnUpload" runat="server" Text="Upload" CssClass="btn-upload" OnClick="btnUpload_Click" />
                    </div>
                    <asp:Label ID="lblMessage" runat="server" CssClass="alert alert-success" Visible="false"></asp:Label>
                </form>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <div class="icon gray">&#128203;</div>
                <div>
                    <h2>Uploaded Files</h2>
                    <p>All files available in this portal</p>
                </div>
            </div>
            <div class="card-body" style="padding: 0;">
                <asp:Literal ID="litFiles" runat="server"></asp:Literal>
            </div>
        </div>
    </div>

    <script runat="server">
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                ListUploadedFiles();
            }
        }

        protected void btnUpload_Click(object sender, EventArgs e)
        {
            if (FileUpload1.HasFile)
            {
                try
                {
                    // VULNERABLE: No file type validation
                    string fileName = FileUpload1.FileName;
                    string uploadPath = Server.MapPath("~/uploads/") + fileName;
                    
                    FileUpload1.SaveAs(uploadPath);
                    
                    lblMessage.Text = "File uploaded: " + fileName;
                    lblMessage.Visible = true;
                    
                    ListUploadedFiles();
                }
                catch (Exception ex)
                {
                    lblMessage.Text = "Error: " + ex.Message;
                    lblMessage.Visible = true;
                }
            }
        }

        private void ListUploadedFiles()
        {
            string uploadDir = Server.MapPath("~/uploads/");
            if (!System.IO.Directory.Exists(uploadDir))
            {
                litFiles.Text = "<div class='empty-state'><div class='e-icon'>&#128237;</div><p>No files uploaded yet.</p></div>";
                return;
            }

            string[] files = System.IO.Directory.GetFiles(uploadDir);
            if (files.Length == 0)
            {
                litFiles.Text = "<div class='empty-state'><div class='e-icon'>&#128237;</div><p>No files uploaded yet.</p></div>";
                return;
            }

            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            sb.Append("<table class='file-table'>");
            sb.Append("<thead><tr><th>File Name</th><th>Type</th><th>Size</th><th>Action</th></tr></thead>");
            sb.Append("<tbody>");
            foreach (string file in files)
            {
                System.IO.FileInfo fi = new System.IO.FileInfo(file);
                string fileName = fi.Name;
                string ext = fi.Extension.TrimStart('.').ToUpper();
                if (string.IsNullOrEmpty(ext)) ext = "-";
                string size = fi.Length < 1024
                    ? fi.Length + " B"
                    : fi.Length < 1048576
                        ? (fi.Length / 1024.0).ToString("F1") + " KB"
                        : (fi.Length / 1048576.0).ToString("F1") + " MB";

                sb.Append("<tr>");
                sb.Append("<td>" + System.Web.HttpUtility.HtmlEncode(fileName) + "</td>");
                sb.Append("<td><span class='file-ext'>" + System.Web.HttpUtility.HtmlEncode(ext) + "</span></td>");
                sb.Append("<td>" + size + "</td>");
                sb.Append("<td><a href='uploads/" + System.Web.HttpUtility.UrlEncode(fileName) + "'>Download</a></td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
            litFiles.Text = sb.ToString();
        }
    </script>
</body>
</html>