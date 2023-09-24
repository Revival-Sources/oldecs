import * as axios_1 from 'axios';

const acl = axios_1.default.create({
    headers: {
        'user-agent': 'GameServer/1.0',
    }
});

async function createsoaprequest(script:string, jobId:string) {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <OpenJobEx xmlns="http://roblox.com/">
            <job>
                <id>${jobId}</id>
                <category>0</category>
                <cores>1</cores>
                <expirationInSeconds>43200</expirationInSeconds>
            </job>
            <script>
                <name>GameStart</name>
                <script>
                <![CDATA[
                ${script}
                ]]>
                </script>
            </script>
        </OpenJobEx>
      </soap:Body>
    </soap:Envelope>`
    return xml;
}
(async() => {
    const request = await createsoaprequest(`print("Hi")`, "job")
    // console.log(request)
    console.log(request);
})()