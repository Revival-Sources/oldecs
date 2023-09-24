using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;

namespace soapframework
{
    public class SOAP
    {
        private static readonly string soapEndpoint = "http://localhost:64989/"; // Replace with the actual SOAP endpoint URL

        public static async Task<string> execute(string script)
        {
            await Task.Delay(TimeSpan.FromSeconds(1));
            // Create the SOAP request body
            string xml = $@"<?xml version=""1.0"" encoding=""utf-8""?>
<soap:Envelope xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
  <soap:Body>
    <OpenJobEx xmlns=""http://roblox.com/"">
        <job>
            <id>job</id>
            <category>0</category>
            <cores>1</cores>
            <expirationInSeconds>43200</expirationInSeconds>
        </job>
        <script>
            <name>GameStart</name>
            <script>
            <![CDATA[
            {script}
            ]]>
            </script>
        </script>
    </OpenJobEx>
  </soap:Body>
</soap:Envelope>";
            try {
                HttpClient client = new HttpClient();
                var content = new StringContent(xml, Encoding.UTF8, "text/xml");
                HttpResponseMessage response = await client.PostAsync(soapEndpoint, content);
                // return response;
                    if (response.IsSuccessStatusCode)
                    {
                        string responseBody = await response.Content.ReadAsStringAsync();
                        return responseBody;
                    }
                    else {
                        return $"Not Success: {response.StatusCode}";
                    }
            }
            catch (Exception ex)
            {
                return $"An unexpected error occurred: {ex.Message}";
            }
        }
    }
}