const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser')
const crypto = require('crypto');
const { Pool } = require('pg');
const argon2 = require('argon2');
// const { v4: uuidv4 } = require('uuid');
app.use("/marketplace/submitpurchase", express.urlencoded({ extended: true }));
app.use("/marketplace/validatepurchase", express.urlencoded({ extended: true }));
app.use("/game/load-place-info", express.urlencoded({ extended: true }));
// app.use("/currency/balance", express.json());
// const staffList = [1, 2,3];
const dbConfig = {
  host: '127.0.0.1',
  database: 'bloxie',
  user: 'postgres',
  password: 'bloxie@',
};
const RateLimit = require('express-rate-limit');
const gueston = false
// Configure rate limiter options
const rateLimitOptions = {
  windowMs: 60 * 1000, // 1 minute
  max: 50, // Max number of requests per windowMs
  message: 'Too many requests, please try again later.',
  headers: true,
};
const SECRET_KEY = "0x4AAAAAAAGfHOyty3Jpx_f3eAQn4ATMsV0"
async function rccjson(mode, type, args, port, assetid, jobid, gameid) {
  const moder = mode
  let arguments = '';
  args.forEach((arg, index) => {
      if (parseInt(arg)) {
    arguments += `         ${arg}`;
      } else {
          arguments += `         "${arg}"`;
      }
      if (index !== args.length - 1) {
          arguments += ',\n';
        } else {
          arguments += '\n';
        }
  });
  if (moder == "Thumbnail") {
    const xml = `<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <BatchJobEx
                xmlns="http://roblox.com/">
                <job>
                    <id>{% uuid 'v4' %}</id>
                    <category>1</category>
                    <cores>1</cores>
                    <expirationInSeconds>43200</expirationInSeconds>
                </job>
                <script>
                    <name>Render3</name>
                    <script>
                        <![CDATA[
    {
      "Mode": "${moder}",
      "Settings": {
        "Type": "${type}",
        "PlaceId": 1,
        "UserId": 1,
        "BaseUrl": "www.oldecs.com",
        "MatchmakingContextId": 1,
        "Arguments": [
  ${arguments}
        ]
      },
      "Arguments": {
        "MachineAddress": "127.0.0.1"
      }
    }
                    ]]>
                    </script>
                </script>
            </BatchJobEx>
        </soap:Body>
    </soap:Envelope>`
  const base64 = await axiosClient.post("http://127.0.0.1:64989", xml).then((data) => {
        const { DOMParser } = require('xmldom');
        const parser = new DOMParser()
        const xmlDoc = parser.parseFromString(data.data, 'text/xml');
        const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
        return value;
    })
    return base64;
  } else {
    const randomNumber = generaterandomnumber(0, 100000)
    console.log(`Args: ${randomNumber}, ${gameid}, ${jobid}, ${type}, ${assetid}, ${port}`)
    const xml = `
    <?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <BatchJobEx
                xmlns="http://roblox.com/">
                <job>
                    <id>{% uuid 'v4' %}</id>
                    <category>1</category>
                    <cores>1</cores>
                    <expirationInSeconds>43200</expirationInSeconds>
                </job>
                <script>
                    <name>Game${randomNumber}</name>
                    <script>
                        <![CDATA[
                          {
                            "Mode":"GameServer",
                            "GameId":1,
                            "Settings":{
                               "Type":"Avatar",
                               "PlaceId":1,
                                 "CreatorId":2,
                               "GameId":"Test",
                                 "MachineAddress":"http://127.0.0.1",
                                 "GsmInterval":5,
                                   "MaxPlayers":30,
                             "MaxGameInstances":51,
                              "ApiKey":"",
                             "PreferredPlayerCapacity":30,
                               "DataCenterId":"69420",
                               "PlaceVisitAccessKey":"",
                               "UniverseId":1,
                               "PlaceFetchUrl":"http://www.oldecs.com/asset/?id=1",
                               "MatchmakingContextId":1,
                               "CreatorId":1,
                               "CreatorType":"User",
                               "PlaceVersion":1,
                               "BaseUrl":"www.oldecs.com",
                               "JobId":"Test",
                               "script":"print('Initializing NetworkServer.')",
                               "PreferredPort":53648
                            },
                            "Arguments":{}
                         }    
                    ]]>
                    </script>
                </script>
            </BatchJobEx>
        </soap:Body>
    </soap:Envelope>
   `
    // const xml = `<?xml version="1.0" encoding="utf-8"?>
    // <soap:Envelope
    //     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    //     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    //     xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    //     <soap:Body>
    //         <BatchJobEx
    //             xmlns="http://roblox.com/">
    //             <job>
    //                 <id>{% uuid 'v4' %}</id>
    //                 <category>1</category>
    //                 <cores>1</cores>
    //                 <expirationInSeconds>43200</expirationInSeconds>
    //             </job>
    //             <script>
    //                 <name>Game${randomNumber}</name>
    //                 <script>
    //                     <![CDATA[
    //                       {
    //                         "Mode":"${moder}",
    //                         "GameId":13058,
    //                         "Settings":{
    //                            "Type":"${type}",
    //                            "PlaceId":${gameid},
    //                              "CreatorId":2,
    //                            "GameId":"${jobid}",
    //                              "MachineAddress":"http://127.0.0.1",
    //                              "GsmInterval":5,
    //                                "MaxPlayers":30,
    //                          "MaxGameInstances":51,
    //                           "ApiKey":"",
    //                          "PreferredPlayerCapacity":30,
    //                            "DataCenterId":"69420",
    //                            "PlaceVisitAccessKey":"",
    //                            "UniverseId":${gameid},
    //                            "PlaceFetchUrl":"http://www.oldecs.com/asset/?id=${assetid}",
    //                            "MatchmakingContextId":1,
    //                            "CreatorId":2,
    //                            "CreatorType":"User",
    //                            "PlaceVersion":1,
    //                            "BaseUrl":"www.oldecs.com",
    //                            "JobId":"${jobid}",
    //                            "script":"print('Initializing NetworkServer.')",
    //                            "PreferredPort":${port}
    //                         },
    //                         "Arguments":{}
    //                      }                         
    //                 ]]>
    //                 </script>
    //             </script>
    //         </BatchJobEx>
    //     </soap:Body>
    // </soap:Envelope>`
  const base64 = await axiosClient.post("http://127.0.0.1:64989", xml).then((data) => {
        // const { DOMParser } = require('xmldom');
        // const parser = new DOMParser()
        // const xmlDoc = parser.parseFromString(data.data, 'text/xml');
        // const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
        // return value;
    })
    return base64;
  }
  }
async function validateTurnstileResponse(req) {
  const token = req.query["cf-turnstile-response"];
  const ip = req.headers['CF-Connecting-IP'];

  // Validate the token by calling the
  // "/siteverify" API endpoint.
  let formData = new FormData();
  formData.append('secret', SECRET_KEY);
  formData.append('response', token);
  formData.append('remoteip', ip);
  const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
  const result = await fetch(url, {
    body: formData,
    method: 'POST',
  });
  const res2 = await result.json()
  return res2.success
}
const noratelimiter = true
const limiter = RateLimit(rateLimitOptions);
if (noratelimiter == false) {
app.use('/api/games', limiter);
app.use('/api/catalog', limiter);
app.use('/games', limiter);
app.use('/catalog', limiter);
app.use('/login', limiter);
app.use('/home', limiter);
}
// app.use('/api/games', limiter);
const maintenanceMode = false
const rateLimiter = (req, res, next) => {
  if (noratelimiter == true) {
    next();
    return;
  } 
  const limit = 60; // Maximum number of requests allowed per hour
  const interval = 60 * 60 * 1000;

  // Get the client's IP address or unique identifier
  const key = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

  // Check if the client has exceeded the request limit
  if (!req.app.locals.requests) {
    req.app.locals.requests = {};
  }

  if (!req.app.locals.requests[key]) {
    req.app.locals.requests[key] = [];
  }

  const requests = req.app.locals.requests[key];
  const currentTime = new Date().getTime();

  // Remove expired requests from the array
  while (requests.length > 0 && requests[0] < currentTime - interval) {
    requests.shift();
  }

  // Check if the request limit is exceeded
  if (requests.length >= limit) {
    return res.status(429).send('Too many requests');
  }

  // Add the current request timestamp to the array
  requests.push(currentTime);

  // Continue to the next middleware
  next();
};
app.use(cookieParser());
if (maintenanceMode == true) {
app.get("*", (req, res) =>{
  res.type("application/json")
  res.status(400).send("Access denied.")
})
}
// Create a new instance of the PostgreSQL pool
const pool = new Pool(dbConfig);

// Helper function to execute SQL queries
async function executeQuery(query, values) {
  const client = await pool.connect();
  try {
    const result = await client.query(query, values);
    return result.rows;
  } finally {
    client.release();
  }
}

// Helper function to generate a random cookie string
function generateCookieString(length) {
  const crypto = require('crypto');
  const bytes = crypto.randomBytes(length);
  const stringBuilder = [];

  for (let i = 0; i < bytes.length; i++) {
    stringBuilder.push(bytes[i].toString(16).padStart(2, '0'));
  }

  return stringBuilder.join('');
}
app.post("/render/avatar", async(req, res)=> {
  const userid = req.query.id
  console.log("test")
  let scriptToSend
  console.log("No way")
  axiosClient.get(`https://www.oldecs.com/asset/characterfetchrender.ashx?userid=${userid}`).then(
    (data => {
      axiosClient.get(`https://www.oldecs.com/Asset/BodyColors.ashx?userid=${userid}`).then
    (async (data2) => {
      scriptToSend =  `
      ${fs.readFileSync("scripts/player.lua")}
      `
      const { DOMParser } = require('xmldom');
const parser = new DOMParser();
const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
      const headColor = xmlDoc.getElementsByTagName('int')[0].textContent;
const leftArmColor = xmlDoc.getElementsByTagName('int')[1].textContent;
const leftLegColor = xmlDoc.getElementsByTagName('int')[2].textContent;
const rightArmColor = xmlDoc.getElementsByTagName('int')[3].textContent;
const rightLegColor = xmlDoc.getElementsByTagName('int')[4].textContent;
const torsoColor = xmlDoc.getElementsByTagName('int')[5].textContent;
      // const base64 = await rccjson("Thumbnail","Thumbnail", [data.data, headColor, torsoColor, leftArmColor, rightArmColor, leftLegColor, rightLegColor])
      // console.log(base64)
      // console.log(`Writing ${userid}.png`)
      // await fs.writeFileSync(`C:/project/Avatars/${userid}.png`, Buffer.from(base64, 'base64'))
      // return res.status(200).sendFile(`C:/project/Avatars/${userid}.png`)
      scriptToSend = scriptToSend.replace(`JSON_AVATAR`, data.data)
      // Parse the XML data
// Parse the XML data

// Extract the values from the XML


// Replace the placeholders in your code
scriptToSend = scriptToSend.replace('head22', headColor);
scriptToSend = scriptToSend.replace('leftarm', leftArmColor);
scriptToSend = scriptToSend.replace('leftleg', leftLegColor);
scriptToSend = scriptToSend.replace('rightarm', rightArmColor);
scriptToSend = scriptToSend.replace('rightleg', rightLegColor);
scriptToSend = scriptToSend.replace('torso', torsoColor);
// console.log(scriptToSend)

      // scriptToSend = scriptToSend.replace(`JSON_COLORS`, `"${data2.data}"`)
      // console.log(scriptToSend)
      // console.log(scriptToSend)
      let randomNumber = Math.floor(Math.random() * (951 - 100) + 100);
      console.log(`Rendering ${userid} with job: render${userid} ${randomNumber}`)
    const xml = `<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <OpenJobEx xmlns="http://roblox.com/">
          <job>
              <id>render${userid} ${randomNumber}</id>
              <category>0</category>
              <cores>1</cores>
              <expirationInSeconds>10</expirationInSeconds>
          </job>
          <script>
              <name>GameStart</name>
              <script>
              <![CDATA[
              ${scriptToSend}
              ]]>
              </script>
          </script>
      </OpenJobEx>
    </soap:Body>
    </soap:Envelope>`
    console.log("Posting")
      axiosClient.post("http://127.0.0.1:64990",xml).then(async(data2) => {
        const { DOMParser } = require('xmldom');
        const parser = new DOMParser()
        const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
        const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
        // console.log(value)
        console.log(`Writing ${userid}.png`)
        await fs.writeFileSync(`C:/project/Avatars/${userid}.png`, Buffer.from(value, 'base64'))
        res.status(200).sendFile(`C:/project/Avatars/${userid}.png`)
      })
    })
  })
  )
});
app.get('/Game/Join.ashx', async (req, res) => {
  // if (!req.query.cookie) {
    // res.status(400).send('Cookie is missing');
    // return;
  // }

  const cookieQuery = req.query.cookie;
  const formatString = '--rbxsig%{0}%{1}';

  try {
    const currentDate = new Date();
    const formattedDate = currentDate.toLocaleString();
    const ticket = req.query.t
    const dbResult = await executeQuery('SELECT * FROM users WHERE cookie = $1', [cookieQuery]);
    const user = dbResult[0];
    if (!cookieQuery) {
      const placeid = req.query.placeid
      // console.log(req.params)
      const gameResult = await executeQuery(`SELECT * FROM games WHERE id = $1`, [placeid]);
      // console.log(gameResult)
      const game = gameResult[0]
      let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [placeid]);
      // console.log(game)
      // if (game.playing < 1 && game) {
        // await creategameserver(game.asset_id)
      // }
      if (!game) {
        return
      }
      let portid
      // let gamey = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [placeid]);
      portid = game.port
      const scriptPath = path.join(__dirname, 'pages', 'join.ashx');
      const script = '\r\n' + fs.readFileSync(scriptPath, 'utf-8');
      let modifiedScript = script
      // Extracting username
      try {
        const usernameMatch = ticket.match(/username=([^;]+)/);
        const username = usernameMatch ? usernameMatch[1] : "";
    
    // Extracting userid
        const useridMatch = ticket.match(/userid=([^;]+)/);
        const userid = useridMatch ? useridMatch[1] : "";
    
    // Extracting membership
        const membershipMatch = ticket.match(/membership=([^;]+)/);
        const membership = membershipMatch ? membershipMatch[1] : "";
        let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
        modifiedScript = script.replace('USERNAMEHERE', username ?username : `Guest ${randomNumber}`);
        modifiedScript = modifiedScript.replace('USERIDHERE2', userid ? userid : -1);
      modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
      modifiedScript = modifiedScript.replace('USERIDHERE', userid ? userid : -1);
      modifiedScript = modifiedScript.replace('useridherer', userid ? userid : -1);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', membership || 'None');
      modifiedScript = modifiedScript.replace("53640", portid)
      modifiedScript = modifiedScript.replace("1939", placeid)
      modifiedScript = modifiedScript.replace("RANDOMGUIDHERE", uuidv4())
      const scriptBytes = Buffer.from(modifiedScript, 'utf-8');
    
      // Generate an RSA private key (if you don't already have one)
      const { privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
    
      // Sign the script using the private key and SHA-1 hashing algorithm
      const signer = crypto.createSign('sha1');
      signer.update(scriptBytes);
      const signature = signer.sign(privateKey);
    
      // Encode the signature in base64
      const signatureBase64 = signature.toString('base64');
    
      // Format the script with the base64 signature
      const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);
    
      res.set('Content-Type', 'application/json');
      res.send(formattedScript);
      return
      } catch (e) {
        let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
        modifiedScript = script.replace('USERNAMEHERE', `Guest ${randomNumber}`);
        modifiedScript = modifiedScript.replace('USERIDHERE2', -1);
      modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
      modifiedScript = modifiedScript.replace('USERIDHERE', -1);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', 'None');
      modifiedScript = modifiedScript.replace("53640", portid)
      modifiedScript = modifiedScript.replace("1939", placeid)
      const scriptBytes = Buffer.from(modifiedScript, 'utf-8');
    
      // Generate an RSA private key (if you don't already have one)
      const { privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
    
      // Sign the script using the private key and SHA-1 hashing algorithm
      const signer = crypto.createSign('sha1');
      signer.update(scriptBytes);
      const signature = signer.sign(privateKey);
    
      // Encode the signature in base64
      const signatureBase64 = signature.toString('base64');
    
      // Format the script with the base64 signature
      const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);
    
      res.set('Content-Type', 'application/json');
      res.send(formattedScript);
      }
    }

    if (!user && cookieQuery) {
      res.status(404).send('User not found');
      return;
    }
    let username
    let userId
    if (cookieQuery) {
      username = user.username;
      userId = user.id;
    }

    const scriptPath = path.join(__dirname, 'pages', 'join.ashx');
    const script = '\r\n' + fs.readFileSync(scriptPath, 'utf-8');

    // Perform the necessary replacements in the script
    let modifiedScript = script
    if (cookieQuery) {
      modifiedScript = script.replace('USERNAMEHERE', username);
      modifiedScript = modifiedScript.replace('USERIDHERE2', `${userId.toString()}`);
    modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
    modifiedScript = modifiedScript.replace('USERIDHERE', userId.toString());
    modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', user.membership || 'None');
    } else if (!cookieQuery) {
      let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
      modifiedScript = script.replace('USERNAMEHERE', `Guest ${randomNumber}`);
      modifiedScript = modifiedScript.replace('USERIDHERE', `-1`);
      modifiedScript = modifiedScript.replace('USERIDHERE2', `-1`);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', 'None');
      const stringtoreplace = `DATEHERE;ewtG0BFnAtFJEQAdSi2CXBVCwE2QuuTyWcWSq1D1iehqtmuQL7q/kBdLntpGrlyGRlTkZwsQTcG8azv2oKSf2zHmQvdq9iEgRy9mXqAkbDJMftq4sqFjif8Y20dCYYTCatG7Dse7P+FTLZNQqR/Xp9mhh6nzVVrFjlLL5UAXsxCFnYU6YsJbtQhM21i+lbb67dNmsin3TKTqWZNQhTaZuxagQXICfCILk+9csD7W/+f7R1l6simuxGIjaT4JshX3BjqrL6U7O4yy37ZAxTEkIvUuZmkHr2WRr4TtWUYSjGTE0ylV+6h31IE/iwEQe91mDP600hyNc7BjkRTXWG5Avg==;pCi0ISsnpOSOfhnLlsdDFodtlx07v7kZHctrIOWFSF9hNCO3RSSg5Epnrmyym0GbuLlpvNjFGTjoWTt4Ax96Ylp1RsYpHRg6G+WBJfwv9L88Os+lPzMYgf5LuoAgsIlcvzR0tYmkUVc4+A2zaQpNVGavHwfPPdkmcxsEHMEke5rnFQzye8nqKwOJpG+8lIbRYEgfRm8bzgLBW7pdD+ufNWq9162YUO6AfoEZTXoHoefOczYW6C4FyIUBjL3kn/VaJwSuceICuF5Q4jxZyP3Qt+blztqSLu0QboSkym01CcY6U4dwtOE3eV9S9uPDt4QBh+PdtTvHqcSN/K5udDx/vA==;2`
      modifiedScript = modifiedScript.replace(stringtoreplace, ``)
    }
    modifiedScript = modifiedScript.replace("RANDOMGUIDHERE", uuidv4())

    // Convert the script to bytes
    const scriptBytes = Buffer.from(modifiedScript, 'utf-8');

    // Generate an RSA private key (if you don't already have one)
    const { privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    // Sign the script using the private key and SHA-1 hashing algorithm
    const signer = crypto.createSign('sha1');
    signer.update(scriptBytes);
    const signature = signer.sign(privateKey);

    // Encode the signature in base64
    const signatureBase64 = signature.toString('base64');

    // Format the script with the base64 signature
    const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);

    res.set('Content-Type', 'application/json');
    res.send(formattedScript);
  } catch (error) {
    console.error('Error executing SQL query:', error);
    res.status(500).send('Internal Server Error');
  }
});
const sign = true
app.all('/Game/Join2018.ashx', async (req, res) => {
  // if (!req.query.cookie) {
    // res.status(400).send('Cookie is missing');
    // return;
  // }

  const cookieQuery = req.query.cookie;
  const formatString = '--rbxsig%{0}%{1}';

  try {
    const currentDate = new Date();
    const formattedDate = currentDate.toLocaleString();
    const ticket = req.query.t
    const dbResult = await executeQuery('SELECT * FROM users WHERE cookie = $1', [cookieQuery]);
    const user = dbResult[0];
    if (!cookieQuery) {
      const placeid = req.query.placeid
      let game
      let gameResult
      if (!placeid) {
       gameResult = await executeQuery(`SELECT * FROM games WHERE id = $1`, [1]);
        // console.log(gameResult)
        game = gameResult[0]
      } else {
        gameResult = await executeQuery(`SELECT * FROM games WHERE id = $1`, [placeid]);
        // console.log(gameResult)
        game = gameResult[0]
      }
      // console.log(req.params)
      let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [1]);
      // console.log(game)
      // if (game.playing < 1 && game) {
        // await creategameserver(game.asset_id)
      // }
      if (!game) {
        return res.status(404).send("game not found lmfao!")
      }
      let portid
      // let gamey = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [placeid]);
      portid = game.port
      const scriptPath = path.join(__dirname, 'pages', 'join2018.ashx');
      const script = sign ? '\r\n' + fs.readFileSync(scriptPath, 'utf-8') : fs.readFileSync(scriptPath, 'utf-8');
      let modifiedScript = script
      // Extracting username
      try {
        
        const usernameMatch = ticket.match(/username=([^;]+)/);
        const username = usernameMatch ? usernameMatch[1] : "";
    
    // Extracting userid
        const useridMatch = ticket.match(/userid=([^;]+)/);
        const userid = useridMatch ? useridMatch[1] : "";
    
    // Extracting membership
        const membershipMatch = ticket.match(/membership=([^;]+)/);
        const membership = membershipMatch ? membershipMatch[1] : "";
        let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
        modifiedScript = script.replace('USERNAMEHERE', username ?username : `Guest ${randomNumber}`);
        modifiedScript = modifiedScript.replace('USERIDHERE2', userid ? userid : -1);
      modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
      modifiedScript = modifiedScript.replace('USERIDHERE', userid ? userid : -1);
      modifiedScript = modifiedScript.replace('useridherer', userid ? userid : -1);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', membership || 'None');
      modifiedScript = modifiedScript.replace("53640", portid)
      modifiedScript = modifiedScript.replace("1939", placeid)
      modifiedScript = modifiedScript.replace("RANDOMGUIDHERE", uuidv4())
      const scriptBytes = Buffer.from(modifiedScript, 'utf-8');
      if (sign) {
        modifiedScript = modifiedScript.replace("--rbxsig%JwjE0x5uYjBTzlQxiL9yOxr+kgfMttA/VfGdVVRI9zJ+emY8XITOcLmqxryZiRmq5HA5NA3HBmTOq8HspTZdDtm2LdqFHY8aY9cjyEsxWKw/hCGRersXdiCZDxxaVKC9Co6YBwh0LVcKy60mJSRrUOyuiSG4fK8NSRf8qQEfuqs=%", "")
      }
    
      // Generate an RSA private key (if you don't already have one)
      const { privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
    
      // Sign the script using the private key and SHA-1 hashing algorithm
      const signer = crypto.createSign('sha1');
      signer.update(scriptBytes);
      const signature = signer.sign(privateKey);
    
      // Encode the signature in base64
      const signatureBase64 = signature.toString('base64');
      // Format the script with the base64 signature
      const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);
    
      res.set('Content-Type', 'application/json');
      res.send(sign ? formattedScript : modifiedScript);
      return
      } catch (e) {
        let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
        modifiedScript = script.replace('USERNAMEHERE', `Guest ${randomNumber}`);
        modifiedScript = modifiedScript.replace('USERIDHERE2', -1);
      modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
      modifiedScript = modifiedScript.replace('USERIDHERE', -1);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', 'None');
      modifiedScript = modifiedScript.replace("53640", portid)
      modifiedScript = modifiedScript.replace("1939", placeid)
      const scriptBytes = Buffer.from(modifiedScript, 'utf-8');
    
      // Generate an RSA private key (if you don't already have one)
      const { privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
    
      // Sign the script using the private key and SHA-1 hashing algorithm
      const signer = crypto.createSign('sha1');
      signer.update(scriptBytes);
      const signature = signer.sign(privateKey);
    
      // Encode the signature in base64
      const signatureBase64 = signature.toString('base64');
    
      // Format the script with the base64 signature
      const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);
    
      res.set('Content-Type', 'application/json');
      res.send(sign ? formattedScript : modifiedScript);
      }
    }

    if (!user && cookieQuery) {
      res.status(404).send('User not found');
      return;
    }
    let username
    let userId
    if (cookieQuery) {
      username = user.username;
      userId = user.id;
    }

    const scriptPath = path.join(__dirname, 'pages', 'join.ashx');
    const script = '\r\n' + fs.readFileSync(scriptPath, 'utf-8');

    // Perform the necessary replacements in the script
    let modifiedScript = script
    if (cookieQuery) {
      modifiedScript = script.replace('USERNAMEHERE', username);
      modifiedScript = modifiedScript.replace('USERIDHERE2', `${userId.toString()}`);
    modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
    modifiedScript = modifiedScript.replace('USERIDHERE', userId.toString());
    modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', user.membership || 'None');
    } else if (!cookieQuery) {
      let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
      modifiedScript = script.replace('USERNAMEHERE', `Guest ${randomNumber}`);
      modifiedScript = modifiedScript.replace('USERIDHERE', `-1`);
      modifiedScript = modifiedScript.replace('USERIDHERE2', `-1`);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', 'None');
      const stringtoreplace = `DATEHERE;ewtG0BFnAtFJEQAdSi2CXBVCwE2QuuTyWcWSq1D1iehqtmuQL7q/kBdLntpGrlyGRlTkZwsQTcG8azv2oKSf2zHmQvdq9iEgRy9mXqAkbDJMftq4sqFjif8Y20dCYYTCatG7Dse7P+FTLZNQqR/Xp9mhh6nzVVrFjlLL5UAXsxCFnYU6YsJbtQhM21i+lbb67dNmsin3TKTqWZNQhTaZuxagQXICfCILk+9csD7W/+f7R1l6simuxGIjaT4JshX3BjqrL6U7O4yy37ZAxTEkIvUuZmkHr2WRr4TtWUYSjGTE0ylV+6h31IE/iwEQe91mDP600hyNc7BjkRTXWG5Avg==;pCi0ISsnpOSOfhnLlsdDFodtlx07v7kZHctrIOWFSF9hNCO3RSSg5Epnrmyym0GbuLlpvNjFGTjoWTt4Ax96Ylp1RsYpHRg6G+WBJfwv9L88Os+lPzMYgf5LuoAgsIlcvzR0tYmkUVc4+A2zaQpNVGavHwfPPdkmcxsEHMEke5rnFQzye8nqKwOJpG+8lIbRYEgfRm8bzgLBW7pdD+ufNWq9162YUO6AfoEZTXoHoefOczYW6C4FyIUBjL3kn/VaJwSuceICuF5Q4jxZyP3Qt+blztqSLu0QboSkym01CcY6U4dwtOE3eV9S9uPDt4QBh+PdtTvHqcSN/K5udDx/vA==;2`
      modifiedScript = modifiedScript.replace(stringtoreplace, ``)
    }
    modifiedScript = modifiedScript.replace("RANDOMGUIDHERE", uuidv4())

    // Convert the script to bytes
    const scriptBytes = Buffer.from(modifiedScript, 'utf-8');

    // Generate an RSA private key (if you don't already have one)
    const { privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    // Sign the script using the private key and SHA-1 hashing algorithm
    const signer = crypto.createSign('sha1');
    signer.update(scriptBytes);
    const signature = signer.sign(privateKey);

    // Encode the signature in base64
    const signatureBase64 = signature.toString('base64');

    // Format the script with the base64 signature
    const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);

    res.set('Content-Type', 'application/json');
    res.send(formattedScript);
  } catch (error) {
    console.error('Error executing SQL query:', error);
    res.status(500).send('Internal Server Error');
  }
});
app.all("/favicon.ico", (req,res)=>{
  try {
    res.status(200).sendFile(path.join(__dirname, "Roblox.ico"))
  } catch (e) {
    res.status(400).type("application/json").send("error")
  }
})
app.get('/Game/PlaceLauncher.ashx', async(req, res) => {
  console.log(`Client making request to placelauncher`)

  const cookieQuery = req.query.cookie;
  const ticket = req.query.t
  if (cookieQuery) {
    const fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'PlaceLauncher.ashx'), 'utf-8');
    const modifiedContent = fileContent.replace("?cookie=cookie", `?cookie=${cookieQuery}`).replace('cookie=cookie', cookieQuery);
    
  
    res.set('Content-Type', 'application/json');
    res.send(modifiedContent);
  } else if (!cookieQuery || ticket && req.query.placeid) {
    console.log(req.query)
  const fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'PlaceLauncher.ashx'), 'utf-8');
  let modifiedContent = fileContent.replace("?cookie=cookie", `?placeid=${req.query.placeid}&t=${ticket}`).replace('cookie=cookie', ``);
  const resu = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid])
  console.log(resu)
  let jobid
  // console.log(resu[0])
  if (resu[0] && resu[0].running == false) { 
    console.log("Starting server lul")
    await creategameserver(req.query.placeid, resu[0].asset_id, res)
  }
  let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [req.query.placeid]);
  if (runninggames) {
    console.log(runninggames)
    let game = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid]);
    console.log(game[0])
    jobid = game[0].job_id
  }
  modifiedContent = modifiedContent.replace("testing123", jobid)
  

  res.set('Content-Type', 'application/json');
  res.send(modifiedContent);
  } else if (ticket && req.query.placeid) {
    const fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'PlaceLauncher.ashx'), 'utf-8');
    const resu = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid])
    let jobid
    // console.log(resu[0])
    if (resu[0].running == false && resu[0]) {
      await creategameserver(req.query.placeid, resu[0].asset_id, res)
    }
    let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [req.query.placeid]);
    if (runninggames) {
      console.log(runninggames)
      let game = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid]);
      console.log(game[0])
      jobid = game[0].job_id
    }
    let modifiedContent = fileContent.replace("?cookie=cookie", `?t=${ticket}&placeid=${req.query.placeid}`).replace('cookie=cookie', ticket);
    modifiedContent = modifiedContent.replace("testing123", jobid)
    res.type("application/json")
    res.send(modifiedContent)
  }
});
app.all('/Game/PlaceLauncher2018.ashx', async(req, res) => {
  console.log(`Client making request to placelauncher 2018`)

  const cookieQuery = req.query.cookie;
  const ticket = req.query.t
  if (cookieQuery) {
    const fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'PlaceLauncher2018.ashx'), 'utf-8');
    const modifiedContent = fileContent.replace("?cookie=cookie", `?cookie=${cookieQuery}`).replace('cookie=cookie', cookieQuery);
    
  
    res.set('Content-Type', 'application/json');
    res.send(modifiedContent);
  }else if (ticket && !req.query.placeid) {
    const fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'PlaceLauncher2018.ashx'), 'utf-8');
    const resu = await executeQuery(`SELECT * FROM games WHERE id = $1`, [1])
    let jobid
    // console.log(resu[0])
    if (resu[0].running == false && resu[0]) {
      await creategameserver(1, resu[0].asset_id, res)
    }
    let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [1]);
    if (runninggames) {
      console.log(runninggames)
      let game = await executeQuery(`SELECT * FROM games WHERE id = $1`, [1]);
      console.log(game[0])
      jobid = game[0].job_id
    }
    let modifiedContent = fileContent.replace("?cookie=cookie", `?t=${ticket}`).replace('cookie=cookie', ticket);
    modifiedContent = modifiedContent.replace("testing123", jobid)
    res.type("application/json")
    res.send(modifiedContent)
  } else if (!cookieQuery || ticket && req.query.placeid) {
    console.log(req.query)
  const fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'PlaceLauncher2018.ashx'), 'utf-8');
  let modifiedContent = fileContent.replace("?cookie=cookie", `?placeid=${req.query.placeid}&t=${ticket}`).replace('cookie=cookie', ``);
  const resu = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid])
  console.log(resu)
  let jobid
  // console.log(resu[0])
  if (resu[0] && resu[0].running == false) { 
    console.log("Starting server lul")
    await creategameserver(req.query.placeid, resu[0].asset_id, res)
  }
  let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [req.query.placeid]);
  if (runninggames) {
    console.log(runninggames)
    let game = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid]);
    console.log(game[0])
    jobid = "Test"
  }
  modifiedContent = modifiedContent.replace("testing123", jobid)
  

  res.set('Content-Type', 'application/json');
  res.json({"jobId": jobid, "status": 2,"joinScriptUrl": `https://www.oldecs.com/Game/Join2018.ashx?t=${req.query.t}&placeid=${req.query.placeid}`, "authenticationUrl": "https://www.oldecs.com/Login/Negotiate.ashx","authenticationTicket": req.query.t,"message":null});
  }
});


app.post("/game/visit/:placeid", async(req, res) => {
 await executeQuery(`UPDATE games SET playing = playing + 1 WHERE id = ${req.params.placeid}`)
 await executeQuery(`UPDATE games SET visits = visits + 1 WHERE id = ${req.params.placeid}`)
})

app.post("/game/leave/:placeid", async(req, res) => {
  await executeQuery(`UPDATE games SET playing = playing - 1 WHERE id = ${req.params.placeid}`)
  const resu = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.params.placeid])
  if (resu[0].playing == 0 || resu[0].playing < 1) {
    shutdowngameserver(req.params.placeid,req)
  }
})
async function generateTicket(length, cookie) {
  const crypto = require('crypto');
  const bytes = crypto.randomBytes(length);
  const stringBuilder = [];

  for (let i = 0; i < bytes.length; i++) {
    stringBuilder.push(bytes[i].toString(16).padStart(2, '0').toUpperCase());
  }
  const query = "SELECT * FROM users WHERE cookie = $1";
  const values = [cookie];
  const users = await executeQuery(query, values);
  if (users[0]) {
    stringBuilder.push(`;username=${users[0].username};userid=${users[0].id};membership=${users[0].membership}`)
  }
  return stringBuilder.join('');
}
app.post("/Login/NewAuthTicket", async(req, res) => {
  const cookiestring = (await generateTicket(20, req.cookies?.OLDECS_SECURITY))
  if (gueston || req.cookies?.OLDECS_SECURITY) {
    res.send(cookiestring)
  } else {
    res.send("Not logged in.")
  }
})

app.get("/test/page", (req, res) => {
  const fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'Admin', 'testpage.cshtml'), 'utf-8');
  res.send(fileContent)
})

app.get("/games/:gameid", async(req, res) => {
  const placeid = req.params.gameid
  let fileContent = fs.readFileSync(path.join(__dirname, 'pages', 'game.cshtml'), 'utf-8');
  const query = `SELECT * FROM games WHERE ID = $1`
  const values = [placeid]
  const games = await executeQuery(query, values)
  const game = games[0]
  if (!game) {
    return res.status(404).redirect("/home")
  }
  const user = await executeQuery(`SELECT * FROM users WHERE username = $1`, [game.creator_name])
  let filec = fileContent.replace("%PLACEIDHERE%", placeid)
    .replace("USERNAME", game.creator_name)
    .replace("USERIDHERE", user[0].id)
    .replace("Game Name", `${game.name}`)
    .replace("This is a description of the game.", `${game.description}`)
    .replace(`ACTIVE`, `${game.playing}`)
    .replace("SERVER SIZE", "Infinite")
    .replace("UPDATED DATE","")
    .replace("VISITS", game.visits)
    .replace("gameidherelul", game.id)
    .replace("gamenamelol", `${game.name}`)
    .replace("gamedescriptionlol", `${game.description}`);
  res.send(filec)
})

app.get('/Login/Negotiate.ashx', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Pages', 'negotiate.ashx');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  app.post('/Login/Negotiate.ashx', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Pages', 'negotiate.ashx');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  app.get('/GetAllowedMD5Hashes', (req, res) => {
    const filePath = path.join(__dirname, 'Pages', 'allowedmd5hashes.ashx');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.send(fileContent);
  })
  app.get("/game/logout.aspx", (req, res) => {
  })


  app.get('/request-error', async (req, res) => {
    const code = req.query["code"]
    // const filePath = path.join(__dirname, 'Pages', 'error404.cshtml');
    // const fileContent = fs.readFileSync(filePath, 'utf-8');
    // console.log(code)
    if (!code) {
      res.contentType("application/json")
      res.send("No status code.")
      return
    }
    // res.contentType("application/json")
    fs.readFile(`pages/error${code}.cshtml`, "utf8", async(err, data) => {
      if (err) {
        console.error("Error reading error404.cshtml:", err);
        res.status(500).send("Internal Server Error");
        return;
      }
      const query = "SELECT * FROM users WHERE cookie = $1";
      const values = [req.cookies?.OLDECS_SECURITY];
      const users = await executeQuery(query, values);
      // console.log

      const user = users[0]
      if (!user) {
        res.status(400).send("Bad Request")
        return
      }
      let filec = data
      filec = filec.replace("ROBUXHERE", user.robux).replace("TIXHERE", user.tix)
      res.send(filec);
    });
  })
  
  app.get("/api/image/error404", (req, res) => {
    const filePath = path.join(__dirname, 'static', 'builderman.png');
    res.sendFile(filePath);
  })
  app.get('/Setting/QuietGet/ClientAppSettings', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Pages', 'fflags.cshtml');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  
  app.get('/Setting/QuietGet/ClientSharedSettings', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Pages', 'fflags.cshtml');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  
  app.get('/Game/Visit.ashx', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Pages', 'visit.ashx');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  
  app.get('/game/validate-machine', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Pages', 'validatemachine.cshtml');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  
  app.get('/Game/GetCurrentUser.ashx', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Pages', 'currentuser.ashx');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  app.get("/game/loadplaceinfo.ashx", (req, res) => {
    res.type('application/json')
    res.status(200).send(`--rbxsig%VPe5fN9+/VuGC69IazwcGYVfG4jpEVJJigebnAWV3LSLIhq+vHg0WAf+T3XqHN7ejvIfnjZqvAsEtMz1aNPqo82oDSgIb/s/a+mf5zF3KR8HGYALoaR+InlVIclKMkNZPkg5UB440SHBhpFQG5MxnuFBK7R3oJoogNLOZ2VO0hs=%
    -- Loaded by StartGameSharedScript --
    
    pcall(function() game:GetService("SocialService"):SetFriendUrl("http://www.oldecs.com/Game/LuaWebService/HandleSocialRequest.ashx?method=IsFriendsWith&playerid=%d&userid=%d") end)
    pcall(function() game:GetService("SocialService"):SetBestFriendUrl("http://www.oldecs.com/Game/LuaWebService/HandleSocialRequest.ashx?method=IsBestFriendsWith&playerid=%d&userid=%d") end)
    pcall(function() game:GetService("SocialService"):SetGroupUrl("http://www.oldecs.com/Game/LuaWebService/HandleSocialRequest.ashx?method=IsInGroup&playerid=%d&groupid=%d") end)
    pcall(function() game:GetService("SocialService"):SetGroupRankUrl("http://www.oldecs.com/Game/LuaWebService/HandleSocialRequest.ashx?method=GetGroupRank&playerid=%d&groupid=%d") end)
    pcall(function() game:GetService("SocialService"):SetGroupRoleUrl("http://www.oldecs.com/Game/LuaWebService/HandleSocialRequest.ashx?method=GetGroupRole&playerid=%d&groupid=%d") end)
    pcall(function() game:GetService("GamePassService"):SetPlayerHasPassUrl("http://www.oldecs.com/Game/GamePass/GamePassHandler.ashx?Action=HasPass&UserID=%d&PassID=%d") end)
    pcall(function() game:GetService("MarketplaceService"):SetProductInfoUrl("http://www.oldecs.com/marketplace/productinfo?assetId=%d") end)
    pcall(function() game:GetService("MarketplaceService"):SetDevProductInfoUrl("http://www.oldecs.com/marketplace/productDetails?productId=%d") end)
    pcall(function() game:GetService("MarketplaceService"):SetPlayerOwnsAssetUrl("http://www.oldecs.com/ownership/hasasset?userId=%d&assetId=%d") end)
    pcall(function() game:SetPlaceVersion(1) end)`)
  })
  app.get('/marketplace/productinfo', async(req, res) => {
    const resu = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.assetId])
    const resu3 = await executeQuery(`SELECT * FROM items WHERE id = $1`, [req.query.assetId])
    const game = resu[0]
    const item = resu3[0]

    // console.log(game[0])
    if (!game && !item) {
      res.redirect(`https://economy.roblox.com/v2/assets/${req.query.assetId}/details`)
    } else if (game) {
      res.type("application/json")
      const resu2 = await executeQuery(`SELECT * FROM users WHERE username = $1`, [game.creator_name])
      const user = resu2[0]
      res.send(`{"TargetId":${game.id},"ProductType":"User Product","AssetId":${game.id},"ProductId":${game.id},"Name":"${game.name}","Description":"${game.description}","AssetTypeId":9,"Creator":{"Id":${user.id},"Name":"${game.creator_name}","CreatorType":"User","CreatorTargetId":1,"HasVerifiedBadge":true},"IconImageAssetId":${game.id},"Created":1686062592,"Updated":null,"PriceInRobux":null,"PriceInTickets":null,"Sales":0,"IsNew":false,"IsForSale":false,"IsPublicDomain":false,"IsLimited":false,"IsLimitedUnique":false,"Remaining":null,"MinimumMembershipLevel":0,"ContentRatingTypeId":0,"SaleAvailabilityLocations":null,"SaleLocation":null,"CollectibleItemId":null}`)
    } else if (item) {
        res.type("application/json")
        const resu2 = await executeQuery(`SELECT * FROM users WHERE username = $1`, [item.creator_name])
        const user = resu2[0]
        res.send(`{"TargetId":${item.id},"ProductType":"User Product","AssetId":${item.id},"ProductId":${item.id},"Name":"${item.name}","Description":"${item.description}","AssetTypeId":${item.asset_type},"Creator":{"Id":${item.id},"Name":"${item.creator_name}","CreatorType":"User","CreatorTargetId":${user.id},"HasVerifiedBadge":false},"IconImageAssetId":${item.id},"Created":1686062592,"Updated":null,"PriceInRobux":${item.price},"PriceInTickets":null,"Sales":0,"IsNew":false,"IsForSale":false,"IsPublicDomain":false,"IsLimited":${item.is_limited},"IsLimitedUnique":${item.is_limited_unique},"Remaining":null,"MinimumMembershipLevel":0,"ContentRatingTypeId":0,"SaleAvailabilityLocations":null,"SaleLocation":null,"CollectibleItemId":null}`)
    }
  })
  app.get("/marketplace/productDetails", (req, res) => {
    res.redirect(`https://economy.roblox.com/v2/developer-products/${req.query.productId}/details`)
  })
  app.get('/Game/GamePass/GamePassHandler.ashx', (req, res) => {
    res.status(200).send("true")
  })
  app.get('/Asset/CharacterFetch.ashx', async (req, res) => {
    try {
      const userId = req.query.userid;
  
      // Fetch the asset_ids from user_wearing table
      const query = "SELECT asset_id FROM user_wearing WHERE user_id = $1";
      const values = [userId];
      const results = await executeQuery(query, values);
  
      // Collect the asset IDs
      const assetIds = results.map(result => result.asset_id);
  
      // Retrieve the asset details from the database in a single query
      const assetQuery = "SELECT * FROM items WHERE id = ANY($1)";
      const assetValues = [assetIds];
      const assetResults = await executeQuery(assetQuery, assetValues);
  
      // Create the formatted response
      let response = `https://www.oldecs.com/asset/bodycolors.ashx?userid=${userId}`;
      const gearIds = new Set();
      const accessoryIds = new Set();
      const clothingIds = new Set();
  
      for (const asset of assetResults) {
        const assetId = asset.id;
        const assetType = asset.asset_type;
  
        if (assetType === 19) {
          if (userId === 2) {
            if (!gearIds.has(assetId)) {
              response += `;https://www.oldecs.com/asset/?id=${assetId}`;
              gearIds.add(assetId);
            }
          } else if (!gearIds.has(assetId)) {
            response += `;https://www.oldecs.com/asset/?id=${assetId}`;
            gearIds.add(assetId);
          }
        } else if (assetType === 11) {
          response += `;https://www.oldecs.com/asset/?id=${assetId}`;
          clothingIds.add(assetId)
        }else if (assetType === 12) {
          response += `;https://www.oldecs.com/asset/?id=${assetId}`;
          clothingIds.add(assetId)
         } else if (assetType === 2) {
            response += `;https://www.oldecs.com/asset/?id=${assetId}`;
            clothingIds.add(assetId)
         } else if (assetType !== 19 && assetType !== 12 && assetType !== 11 && assetType !== 2) {
          if (!accessoryIds.has(assetId)) {
            response += `;https://www.oldecs.com/asset/?id=${assetId}`;
            accessoryIds.add(assetId);
          }
        }
      }
  
      res.setHeader('Content-Type', 'application/json');
      res.send(response);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Error occurred while fetching character assets.' });
    }
  });
  app.get('/Asset/CharacterFetchRender.ashx', async (req, res) => {
    try {
      const userId = req.query.userid;
  
      // Fetch the asset_ids from user_wearing table
      const query = "SELECT asset_id FROM user_wearing WHERE user_id = $1";
      const values = [userId];
      const results = await executeQuery(query, values);
  
      // Create the formatted response
      let response = `https://www.oldecs.com/asset/bodycolors.ashx?userid=${userId}`;
      let hasGear = false;
      let hasShirt = false;
      let hasPants = false;
  
      for (const result of results) {
        const assetId = result.asset_id;
  
        // Retrieve the asset details from the database
        const assetQuery = "SELECT asset_type FROM items WHERE id = $1";
        const assetValues = [assetId];
        const assetResults = await executeQuery(assetQuery, assetValues);
  
        // Check if the asset ID is a gear (asset type 19)
        if (assetResults[0].asset_type === 19) {
          if (hasGear) {
            continue; // Skip adding additional gears
          } else {
            hasGear = true; // Set the flag indicating that a gear has been added
          }
        }
  
        // Add the asset to the response
        response += `;https://www.oldecs.com/asset/?id=${assetId}`;
      }
  
      res.setHeader('Content-Type', 'application/json');
      res.send(response);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Error occurred while fetching character assets.' });
    }
  });
  app.get('/logout', (req, res) => {
    // Implement the route logic
    res.clearCookie('OLDECS_SECURITY');
    res.redirect('/login');
  });
  
  app.get('/ownership/hasasset/:path', (req, res) => {
    // Implement the route logic
    const assetPath = req.params.path;
    res.send('true');
  });
  
  app.get('/Thumbs/Avatar.ashx', (req, res) => {
    // Implement the route logic
    const id = req.query.userid;
    res.redirect(`/api/users/${id}/image`)
  });
  app.get('/api/users/:path/image', (req, res) => {
    // Implement the route logic
    const id = req.params.path;
    // const userId = req.query.userid;
    // console.log(id)
    try {
      if (fs.readFileSync(`C:/project/Avatars/${id}.png`)) {
        res.sendFile(`C:/project/Avatars/${id}.png`)
      } else {
       res.sendFile('C:/project/Avatars/placeholder.png');
      }
    } catch (e) {
      res.sendFile('C:/project/Avatars/placeholder.png');
    }
    // });
  });
  function generatePaginationHTML(currentPage, totalPages) {
    let paginationHTML = '<div class="pagination">';
    for (let i = 1; i <= totalPages; i++) {
      if (i === currentPage) {
        paginationHTML += `<span class="current-page">${i}</span>`;
      } else {
        paginationHTML += `<a href="/my/character.aspx?page=${i}" class="page-link">${i}</a>`;
      }
    }
    paginationHTML += '</div>';
    return paginationHTML;
  }
  
  app.get("/my/character.aspx", async (req, res) => {
    const userIdQuery = "SELECT id FROM users WHERE cookie = $1";
    const inventoryQuery = "SELECT * FROM user_inventory WHERE user_id = $1 LIMIT $2 OFFSET $3";
    const wearingQuery = "SELECT * FROM user_wearing WHERE user_id = $1";
    const cookie = req.cookies?.OLDECS_SECURITY;
    const userIdRows = await executeQuery(userIdQuery, [cookie]);
    const userId = userIdRows[0].id;
    const page = req.query.page ? parseInt(req.query.page) : 1; // Get page number from query parameter, default to 1
    const itemsPerPage = 5; // Number of items to display per page
  
    // Calculate the offset for pagination
    const offset = (page - 1) * itemsPerPage;
  
    const inventoryRows = await executeQuery(inventoryQuery, [userId, itemsPerPage, offset]);
    const itemQuery = "SELECT * FROM items WHERE id = $1";
    const wearingRows = await executeQuery(wearingQuery, [userId]);
  
    fs.readFile("pages/characterpage.cshtml", "utf8", async (err, fileContent) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Internal Server Error");
      }
  
      let filec = fileContent;
      filec= filec.replace("useridforsavechanges", userId)
      filec= filec.replace("useridforchar", userId)
  
      // Generate HTML for each item in the inventory
      const itemPromises = inventoryRows.map(async (row) => {
        const itemId = row.item_id; // Assuming the column name is "item_id" in the user_inventory table
        const itemRow = await executeQuery(itemQuery, [itemId]);
        const itemTitle = itemRow[0].name; // Assuming the column name is "name" in the items table
        const itemType = itemRow[0].asset_type; // Assuming the column name is "asset_type" in the items table
        const isWearing = wearingRows.some((wearingRow) => wearingRow.asset_id === itemId);
        const wearButtonText = isWearing ? "Remove" : "Wear";
  
        return `
          <div class="item-box" style="background-image:url('/api/catalog/${itemId}/image')"></div>
          <div class="item-info">
            <div class="item-info-title">${itemTitle}</div>
            <div class="item-info-type">Type: ${itemType}</div>
            <button id="wear-button${itemId}" class="wear-button">${wearButtonText}</button>
          </div>
          <script>
          const btn${itemId} = document.getElementById("wear-button${itemId}");
          btn${itemId}.addEventListener('click', function() {
            if (btn${itemId}.textContent === "Remove") {
              btn${itemId}.textContent = "Wear";
              fetch("/api/character/${userId}/remove/${itemId}", { method: "POST" })
                .then(() => {
                  
                })
                .catch(error => {
                  console.error("Error:", error);
                });
            } else {
              btn${itemId}.textContent = "Remove";
              fetch("/api/character/${userId}/wear/${itemId}", { method: "POST" })
                .then(() => {
                  
                })
                .catch(error => {
                  console.error("Error:", error);
                });
            }
          });
        </script>
        `;
      });
  
      const itemHTML = await Promise.all(itemPromises);
  
      // Replace placeholder with generated item HTML
      filec = filec.replace("<!--items-->", itemHTML.join(""));
  
      // Generate pagination links
      const totalItems = await executeQuery("SELECT COUNT(*) as count FROM user_inventory WHERE user_id = $1", [userId]);
      const totalPages = Math.ceil(totalItems[0].count / itemsPerPage);
      const paginationHTML = generatePaginationHTML(page, totalPages);
      filec = filec.replace("<!--pagination-->", paginationHTML);
  
      res.send(filec);
    });
  });

  app.post("/api/character/:userid/wear/:itemid", async(req, res) => {
    const userid = req.params.userid;
    const itemid = req.params.itemid;
    const query = `SELECT * FROM users WHERE id = $1`
    const values = [userid]
    const result = await executeQuery(query, values)
    if (result[0].id != userid) {
    return res.status(400).send("i swear this kid wants to change someone else's avatar")
    }
    const query2 = `SELECT * FROM user_wearing WHERE user_id = $1`
    const values2 = [userid]
    const result2 = await executeQuery(query2, values2)

    // const result3 = await executeQuery(`SELECT * FROM items WHERE id = $1`, [item.id])
    const result4 = await executeQuery(`SELECT * FROM user_wearing WHERE asset_id = $1 AND user_id = $2`, [itemid, userid])
      if (!result4[0]) {
          const insertQuery = `INSERT INTO user_wearing (user_id, asset_id) VALUES ($1, $2)`;
          const insertValues = [userid, itemid];
          await executeQuery(insertQuery, insertValues);
          res.status(200).send("sure")
          return
        } else {
          return res.status(400).send("bye bye u wearing asset type 19 dawg")
        }
    })
  
  app.post("/api/character/:userid/remove/:itemid", async(req, res) => {
    const userid = req.params.userid;
    const itemid = req.params.itemid;
    const query = `SELECT * FROM users WHERE id = $1`
    const values = [userid]
    const result = await executeQuery(query, values)
    if (result[0].id != userid) {
      return res.status(400).send("i swear this kid wants to change someone else's avatar")
    }
    const query2 = `DELETE FROM user_wearing WHERE asset_id = $1 AND user_id = $2`;
    const values2 = [itemid, userid];
    await executeQuery(query2, values2)
  });
  app.post("/api/character/:userid/save", async(req, res) => {
   await axiosClient.post(`https://www.oldecs.com/render/avatar?id=${req.params.userid}`)
   res.status(200).send("Success")
  })
  
  // Function to generate pagination HTML
  app.get("/users/:path/profile", async(req, res) => {
    fs.readFile("pages/userprofile.cshtml", 'utf8', async(err, fileContent) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error reading file');
      }
      let filec = fileContent
      const path = req.params.path;
      const userId = path.split('/')[0];
  
      // Retrieve items and user details
      // const query = `
        // SELECT ui.item_id, i.name, ui.serial 
        // FROM user_inventory ui 
        // INNER JOIN items i ON ui.item_id = i.id 
        // WHERE ui.user_id = $1
      // `;
      const query = `SELECT * FROM users WHERE id = $1`;
      const values = [userId]
      const users = await executeQuery(query, values);
      const user = users[0]
      if (!user) {
        res.redirect("/request-error?code=404")
        return
      }
      // res.contentType('application/json');
      filec = filec.replace("USERNAME", user.username).replace("USERNAME", user.username).replace("USERDESCRIPTION", user.description).replace("Username", user.username).replace("Description", user.description).replace("UserIdHerEbrO", user.id)
      res.send(filec);
    });
  })
  
  app.get('/Thumbs/Asset.ashx', (req, res) => {
    // Implement the route logic
    const userId = req.query.userid;
    res.redirect('/static/img/placeholder.png');
  });
  
  app.get('/static/img/placeholder.png', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'Avatars', 'placeholder.png');
    res.sendFile(filePath);
  });
  app.get('/static/img/robux.png', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'static', 'robux-2.png');
    res.sendFile(filePath);
  });
  app.get('/static/img/tix.png', (req, res) => {
    // Implement the route logic
    const filePath = path.join(__dirname, 'static', 'tix-2.png');
    res.sendFile(filePath);
  });

// const path = require('path');
// const fs = require('fs');

// const fs = require('fs');

const axios = require('axios');
// const path = require('path');

const async = require('async');
const axiosClient = axios.default.create({
  headers: {
      'user-agent': 'OldEcs/1.0',
  }
});

function generaterandomnumber(start, end) {
  let randomNumber = Math.floor(Math.random() * (end - start) + start);
  return randomNumber
}
  app.get("/v1/settings/application", (req, res)=> {
    res.type("application/json")
    res.send(`${fs.readFileSync(`pages/application.cshtml`)}`)
  })
async function creategameserver(gameid, asset_id, res) {
  const games = await executeQuery(`SELECT * FROM games WHERE id = $1`, [gameid]);
  let thing = 53638
  let thing2 = 53680
  const result = await executeQuery(`SELECT * FROM games`, [])
  let runninggames = await executeQuery(`SELECT * FROM running_games`, []);
  const games2 = runninggames.map(async () => {
    thing = thing + 1
  })
  Promise.all(games2)
  if (thing > thing2 - 1) {
    return
  }
  // runninggames.push()
  const port = thing
  const jobId = generateCookieString(10)
  // await rccjson("GameServer", "GameServer", [games[0].asset_id,gameid,port,"https://www.oldecs.com"],port,games[0].asset_id,jobId,gameid).then((async (data) => {
  //   if (data == null) {
  //     res.type("application/json")
  //     res.status(200).json({"jobId": jobId, "status": 2,"joinScriptUrl": `https://www.oldecs.com/Game/Join2018.ashx?placeid=${gameid}`, "authenticationUrl": "https://www.oldecs.com/Login/Negotiate.ashx","authenticationTicket": "","message":null});
  //   } else {
  //     console.log(data)
  //     await executeQuery('INSERT INTO running_games (id) VALUES ($1)', [gameid]);
  //     await executeQuery(`UPDATE games SET running = true WHERE id = $1`, [gameid])
  //     await executeQuery(`UPDATE games SET port = $1 WHERE id = $2`, [thing,gameid])
  //     await executeQuery(`UPDATE games SET job_id = $1 WHERE id = $2`, [jobId, gameid])
  //   }
  // }))
  // return
  const ip = "127.0.0.1"
  const ipport = 64989
  const axios = require('axios');
  // const path = require('path');
  
  // const async = require('async');
  const axiosClient = axios.default.create({
    headers: {
        'user-agent': 'OldEcs/1.0',
    }
  });
  await executeQuery('INSERT INTO running_games (id) VALUES ($1)', [gameid]);
  // runninggames.push(`${gameid};${thing};${jobId}`)
  console.log(runninggames)
  await executeQuery(`UPDATE games SET running = true WHERE id = $1`, [gameid])
  await executeQuery(`UPDATE games SET port = $1 WHERE id = $2`, [thing,gameid])
  await executeQuery(`UPDATE games SET job_id = $1 WHERE id = $2`, [jobId, gameid])
  const fs = require('fs')
  // const games = await executeQuery(`SELECT * FROM games WHERE id = $1`, [gameid]);
  const scriptToSend = `
  local http = game:GetService("HttpService")
  http.HttpEnabled = true
  print(game:GetService('HttpService').HttpEnabled)
  ${fs.readFileSync("gameserver.txt")}
  start(${games[0].asset_id}, ${gameid}, ${port}, "https://www.oldecs.com")
  `
  
  const xml = `<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <OpenJobEx xmlns="http://roblox.com/">
          <job>
              <id>${jobId}</id>
              <category>0</category>
              <cores>1</cores>
              <expirationInSeconds>432000</expirationInSeconds>
          </job>
          <script>
              <name>GameStart</name>
              <script>
              <![CDATA[
              ${scriptToSend}
              ]]>
              </script>
          </script>
      </OpenJobEx>
    </soap:Body>
  </soap:Envelope>`
  axiosClient.post(`http://${ip}:${ipport}`, xml)
}
async function shutdowngameserver(gameid, req) {
  await executeQuery(`UPDATE games SET running = false WHERE id = $1`, [gameid])
  let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [gameid]);
  await executeQuery('DELETE FROM running_games WHERE id = $1', [gameid]);
  const ipport = 64989
  const ip = "127.0.0.1"
  const games = await executeQuery(`SELECT * FROM games WHERE id = $1`, [gameid])
// const path = require('path');
  let jobId = games[0].job_id
// const async = require('async');
const axiosClient = axios.default.create({
  headers: {
      'user-agent': 'OldEcs/1.0',
  }
});
console.log(jobId)
await executeQuery(`UPDATE games SET job_id = null WHERE id = $1`, [gameid])
await executeQuery(`UPDATE games SET port = null WHERE id = $1`, [gameid])
// const fs = require('fs')

const xml = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <CloseJob xmlns="http://roblox.com/" jobID="${jobId}">
        <jobID>${jobId}</jobID>
        <job>
            <id>${jobId}</id>
        </job>
    </CloseJob>
  </soap:Body>
</soap:Envelope>`

axiosClient.post(`http://${ip}:${ipport}`, xml)
return true
}
const MAX_RETRY_ATTEMPTS = 5;
const RETRY_DELAY_MS = 1;

const downloadQueue = async.queue(async (task, callback) => {
  const { assetId, assetPath, res, retryAttempts } = task;

  const assetUrl = `https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`;

  try {
    const response = await axiosClient.get(assetUrl, { responseType: 'arraybuffer' });

    if (response.status === 200) {
      fs.writeFileSync(assetPath, response.data);
      return res.sendFile(assetPath, callback);
    } else {
      throw new Error('Failed to download asset');
    }
  } catch (error) {
    console.error(error);

    if (retryAttempts < MAX_RETRY_ATTEMPTS) {
      // Retry after a delay
      setTimeout(() => {
        const nextRetryAttempts = retryAttempts + 1;
        downloadQueue.push({ assetId, assetPath, res, retryAttempts: nextRetryAttempts });
      }, RETRY_DELAY_MS * 1000);
    } else {
      return res.status(400).send('Failed to download asset');
    }
  }
}, 1);
app.get("/v1.1/avatar-fetch", async(req, res) => {
  res.type("application/json")
  res.status(200).send(`{"resolvedAvatarType":"R15","accessoryVersionIds":[4],"equippedGearVersionIds":[],"backpackGearVersionIds":[],"bodyColorsUrl":"http://www.oldecs.com/Asset/BodyColors.ashx?userId=0","animations":{"Run":969731563},"scales":{"width":1,"height":1,"head":1,"depth":1,"proportion":0,"bodyType":0}}`)
})
app.get("/AbuseReport/InGameChatHandler.ashx", (req, res) => {
  // console.log(req)
  // console.log(req.rawHeaders.toString())
  const postData = {
    // content: req.rawHeaders.toString(),
    // username: 'Webhook Bot',
    // avatar_url: 'https://example.com/avatar.png',
  };  
  // axiosClient.post("https://discord.com/api/webhooks/1128350032693821561/YAvA7dDfx1e-70s4SY8TJAf_3ah8IhBBaJCGd2wEoihbM0cc89CvJjtc-lArf5wUViR_", postData)
})
app.get('/v1/asset', (req, res) => {
  const assetId = req.query.id || req.query.ID;
  // console.log(`Asset id: ${assetId}`);

  if (!assetId) {
    return res.status(400).send('Asset ID not provided');
  }

  if (assetId == 0) {
    res.status(400).send("Ok i will save u the wait")
    return
  }

  // Check if the asset already exists in the "Assets" folder
  const assetPath = path.join(__dirname, 'Assets', assetId);
  if (fs.existsSync(assetPath)) {
    // Asset already exists, send the file as the response
    return res.sendFile(assetPath);
  }

  // Asset doesn't exist, add download task to the queue with initial retryAttempts = 0
  axiosClient.get(`https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`).then((data) => {
    fs.writeFileSync(`Assets/${assetId}`, Buffer.from(data.data))
    res.sendFile(`C:/project/Assets/${assetId}`)
  })
  // res.redirect(`https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`)
  // downloadQueue.push({ assetId, assetPath, res, retryAttempts: 0 });
});
app.get('/asset', async(req, res) => {
  const assetId = req.query.id || req.query.ID;
  // console.log(`Asset id: ${assetId}`);
  // console.log(assetId)

  if (!assetId) {
    console.log("No asset id blud")
    return res.status(400).send('Asset ID not provided');
  }

  if (assetId == 0) {
    res.status(400).send("Ok i will save u the wait")
    return
  }

  // Check if the asset already exists in the "Assets" folder
  const game = await executeQuery(`SELECT * FROM games WHERE id = $1`, [assetId])
  const assetPath = path.join(__dirname, 'Assets', assetId);
  if (fs.existsSync(assetPath)) {
    // Asset already exists, send the file as the response
    return res.sendFile(assetPath);
  } else if (game[0]) {
    return res.status(200).sendFile(path.join(__dirname, "Assets", game[0].asset_id.toString()))
  }

  // Asset doesn't exist, add download task to the queue with initial retryAttempts = 0
  // axiosClient.get(`https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`).then((data) => {
    // fs.writeFileSync(`Assets/${assetId}`, Buffer.from(data.data))
    // res.sendFile(`C:/project/Assets/${assetId}`)
  // })
  // res.redirect(`https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`)
  // downloadQueue.push({ assetId, assetPath, res, retryAttempts: 0 });
});
app.get('//asset', (req, res) => {
  const assetId = req.query.id || req.query.ID;
  console.log(`Asset id: ${assetId}`);

  if (!assetId) {
    return res.status(400).send('Asset ID not provided');
  }

  if (assetId == 0) {
    res.status(400).send("Ok i will save u the wait")
    return
  }

  // Check if the asset already exists in the "Assets" folder
  const assetPath = path.join(__dirname, 'Assets', assetId);
  if (fs.existsSync(assetPath)) {
    // Asset already exists, send the file as the response
    return res.sendFile(assetPath);
  }

  // Asset doesn't exist, add download task to the queue with initial retryAttempts = 0
  res.redirect(`https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`)
  // downloadQueue.push({ assetId, assetPath, res, retryAttempts: 0 });
});
app.get('/Game/LuaWebService/HandleSocialRequest.ashx', rateLimiter, async (req, res) => {
  const filePath = path.join(__dirname, 'Pages', 'luawebservice.ashx');
  const playerid = req.query['playerid'];
  const filePath2 = path.join(__dirname, 'Pages', 'group.ashx');
  let filecontent = fs.readFileSync(path.join(__dirname, 'Pages', 'luawebservice.ashx'), 'utf8');

  res.setHeader('Content-Type', 'application/xml');
  const method = req.query['method'];
  const query = `SELECT * FROM users WHERE id = $1`
  const values = [playerid]
  const users = await executeQuery(query, values)
  const user = users[0]
  if (method === 'GetGroupRank') {
    res.sendFile(filePath2);
  } else if (method === 'IsInGroup') {
    if (user.admin) {
      filecontent = filecontent.replace('false', 'true');
      res.send(filecontent);
    } else {
      res.sendFile(filePath);
    }
  }
});
app.get("/catalog", rateLimiter, async (req, res) => {
  try {
    const page = req.query.page || 1;
    const itemsPerPage = 10;
    const offset = (page - 1) * itemsPerPage;

    const query = "SELECT * FROM items ORDER BY id OFFSET $1 LIMIT $2";
    const values = [offset, itemsPerPage];
    const items = await executeQuery(query, values);

    const query2 = "SELECT * FROM user_inventory WHERE item_id = $1 AND user_id <> $2";
    const renderedItems = await Promise.all(items.map(async (item) => {
      if (item.price != null) {
        const value2 = [item.id, 1];
        const allcopies = await executeQuery(query2, value2);
        if (item.max_copies != 0 && item.max_copies != null) {
          const remaining = Math.max(item.max_copies - allcopies.length, 0);
          if (remaining != 0) {
            return `
              <a href="https://www.oldecs.com/catalog/${item.id}" class="item-box">
                <img src="/api/catalog/${item.id}/image">
                <div id="title2" class="title2">${item.name}</div>
                <div class="remaining">Remaining: ${remaining}</div>
                <div style="color: #fff;" class="price" id="price">Price: ${item.price}</div>
              </a>
            `;
          } else {
            return `
              <a href="https://www.oldecs.com/catalog/${item.id}" class="item-box">
                <img src="/api/catalog/${item.id}/image">
                <div id="title2" class="title2">${item.name}</div>
                <div class="remaining">None Left</div>
              </a>
            `;
          }
        } else {
          return `
            <a href="https://www.oldecs.com/catalog/${item.id}" class="item-box">
              <img src="/api/catalog/${item.id}/image">
              <div class="title2" id="title2">${item.name}</div>
              <div style="color: #fff;" id="price" class="price">Price: ${item.price}</div>
            </a>
          `;
        }
      }
      return null;
    }));

    // Calculate pagination values
    const totalCountQuery = "SELECT COUNT(*) AS total_count FROM items";
    const totalCountResult = await executeQuery(totalCountQuery);
    const totalCount = parseInt(totalCountResult[0].total_count, 10);
    const totalPages = Math.ceil(totalCount / itemsPerPage);

    // Read the catalog HTML template file
    fs.readFile("Pages/catalog.cshtml", "utf8", (err, data) => {
      if (err) {
        console.error("Error reading catalog.cshtml:", err);
        res.status(500).send("Internal Server Error");
        return;
      }

      // Replace the content in the renderedPage
      let renderedPage = data.replace('<div class="popular-items">', `<div class="popular-items">${renderedItems.join('\n')}`);
      // Append pagination links
      renderedPage += generatePaginationLinks(page, totalPages);
      // Send the rendered page as the response
      res.send(renderedPage);
    });
  } catch (error) {
    console.error("Error retrieving items:", error);
    res.status(500).send("Internal Server Error");
  }
});

function generatePaginationLinks(currentPage, totalPages) {
  let links = '<div class="pagination">';
  for (let i = 1; i <= totalPages; i++) {
    if (i === currentPage) {
      links += `<span class="current-page">${i}</span>`;
    } else {
      links += `<a href="/catalog?page=${i}">${i}</a>`;
    }
  }
  links += '</div>';
  return links;
}
app.get("/games", rateLimiter, async (req, res) => {
    const query = "SELECT * FROM games ORDER BY playing DESC";
    const items = await executeQuery(query);
    // const query2 = "SELECT * FROM user_inventory WHERE item_id = $1 AND user_id <> $2";
    const renderedItems = items.map(async (game) => {
        // console.log(allcopies.length)
            const gameitem = `
            <a href="https://www.oldecs.com/games/${game.id}" class="game-box">
              <img src="/api/games/${game.id}/image">
              <div id="title2" class="title2">${game.name}</div>
              <div id="playing" class="playing">Playing: ${game.playing}</div>
            </a>
          `;
        // const catalogItem = `
        // <a href="https://www.oldecs.com/catalog/${item.id}" class="item-box">
        //   <img src="/api/catalog/${item.id}/image">
        //   <div id="title2" class="title2">${item.name}</div>
        //   <div class="remaining">Remaining: A lot</div>
        // </a>
      // `;
        return gameitem;
      })


    fs.readFile("Pages/games.cshtml", "utf8", async(err, data) => {
      if (err) {
        console.error("Error reading games.cshtml:", err);
        res.status(500).send("Internal Server Error");
        return;
      }

      const resolvedItems = await Promise.all(renderedItems);

// Replace the content in the renderedPage
let renderedPage = data.replace('<div class="popular-games">', `<div class="popular-games">${resolvedItems.join('\n')}`);
      const query = "SELECT * FROM users WHERE cookie = $1";
      const values = [req.cookies?.OLDECS_SECURITY];
      const users = await executeQuery(query, values);
      // console.log

      const user = users[0]
      if (user && user.banned == true) {
        res.redirect("/auth/not-approved");
        return;
      }
      // renderedPage = renderedPage.replace("ROBUXHERE", user.robux).replace("TIXHERE", user.tix)
      res.send(renderedPage);
    });
});
app.get("/api/catalog/:path/image", rateLimiter, (req, res) => {

  // res.redirect("/static/img/placeholder.png")
  try {
  if (fs.readFileSync(`C:/project/Icons/${req.params.path}.png`)) {
    res.sendFile(`C:/project/Icons/${req.params.path}.png`)
  } else {
    res.sendFile("C:/project/Avatars/placeholder.png")
  }
} catch (e) {
  res.sendFile("C:/project/Avatars/placeholder.png")
}
    // res.send(data);
  // });
})

app.get("/api/games/:path/image", rateLimiter, async(req, res) => {

  // res.redirect("/static/img/placeholder.png")
  try {
    const games = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.params.path])
  if (fs.readFileSync(`C:/project/Games/${req.params.path}.png`)) {
    res.sendFile(`C:/project/Games/${req.params.path}.png`)
  } else {
    res.sendFile("C:/project/Avatars/placeholder.png")
  }
} catch (e) {
  res.sendFile("C:/project/Avatars/placeholder.png")
}
    // res.send(data);
  // });
})
app.get('/users/:path(*)/canmanage/:path(*)', (req, res) => {
  const filePath = path.join(__dirname, 'pages', 'canmanage.ashx');
  fs.readFile(filePath, 'utf8', (err, fileContent) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error reading file');
    }
    res.contentType('application/json');
    res.send(fileContent);
  });
})
app.get('/game/players/:path(*)', (req, res) => {
  const filePath = path.join(__dirname, 'pages', 'gameplayers.ashx');
  fs.readFile(filePath, 'utf8', (err, fileContent) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error reading file');
    }
    res.send(fileContent);
  });
});


app.post('/api/purchase/:path(*)', rateLimiter, async (req, res) => {
  const itemId = req.params.path;
  const query = "SELECT * FROM items WHERE id = $1";
  const values = [itemId];
  const items = await executeQuery(query, values);

  if (items.length === 0) {
    // Item not found in the database
    res.status(404).send('Item not found');
    return;
  }

  const cookie = req.cookies?.OLDECS_SECURITY;
  const item = items[0];

  const query2 = "SELECT * FROM users WHERE cookie = $1";
  const values2 = [cookie];
  const users = await executeQuery(query2, values2);

  if (users.length === 0) {
    // User not found in the database
    res.status(404).send('User not found');
    return;
  }

  const user = users[0];
  if (user.banned == true) {
    res.redirect("/auth/not-approved");
    return;
  }

  // Check if the user has enough currency
  let currency;
  let currency2
  if (item.currency_type === 1) {
    // Robux
    currency = user.robux - item.price
    currency2 = user.robux
  } else if (item.currency_type === 2) {
    // Tix
    currency = user.tix - item.price
    currency2 = user.tix;
  }

  if (currency2 < item.price) {
    res.status(400).send('Insufficient currency');
    return;
  }

  // Check if the user has exact currency amount as item cost
  if (currency === item.price) {
    currency = 0; // Set currency to 0
  }
  if (item.price == null) {
    return res.status(400).send("Item Offsale")
  }
  // Check if the item is limited unique
  if (item.is_limited_unique) {
    // Retrieve the highest serial number for the item
    const serialQuery = "SELECT MAX(serial) AS highest_serial FROM user_inventory WHERE item_id = $1";
    const serialValues = [item.id];
    const serialResult = await executeQuery(serialQuery, serialValues);
    const highestSerial = serialResult[0].highest_serial || 0;
    // console.log(highestSerial)
    const query2 = "SELECT * FROM user_inventory WHERE item_id = $1 AND user_id <> 1";
    const valu2 = [item.id];
    const allowners = await executeQuery(query2, valu2);
    // Check if the item has available copies
    if (allowners.length >= item.max_copies) {
      res.status(500).send('Item is sold out');
      return;
    }

    const query = "SELECT * FROM user_inventory WHERE user_id = $1 AND item_id = $2";
    const valu = [user.id, item.id];
    const resu = await executeQuery(query, valu);
    if (resu[0]) {
      return res.status(500).send("bro u already own this item :sob:")
    }
    // Increment the highest serial by 1 for the new purchase
    const newSerial = highestSerial + 1;

    // Insert the purchase information with the serial into the user_inventory table
    if (user.id != 1) {
      const insertQuery = "INSERT INTO user_inventory (user_id, item_id, serial) VALUES ($1, $2, $3)";
      const insertValues = [user.id, item.id, newSerial];
      await executeQuery(insertQuery, insertValues);
    }

    // Deduct the cost from the user's currency
    let updateQuery;
    if (item.currency_type === 1) {
      // Robux
      updateQuery = "UPDATE users SET robux = CAST($1 AS INTEGER) - CAST($2 AS INTEGER) WHERE id = $3";
      const updateValues = [user.robux, item.price, user.id];
      await executeQuery(updateQuery, updateValues);
    } else if (item.currency_type === 2) {
      // Tix
      updateQuery = "UPDATE users SET tix = CAST($1 AS INTEGER) - CAST($2 AS INTEGER) WHERE id = $3";
      const updateValues = [item.price, user.tix, user.id];
      await executeQuery(updateQuery, updateValues);
    }
    const owners = await executeQuery(`SELECT * FROM users WHERE username = $1`, [item.creator_name])
    const owner = owners[0]
    let updateQuery2 = "UPDATE users SET robux = CAST($1 AS INTEGER) + CAST($2 AS INTEGER) * 0.7 WHERE id = $3";
    let updateValues2 = [parseInt(owner.robux), parseInt(item.price), owner.id]
    await executeQuery(updateQuery2,updateValues2)
    res.status(200).send(`Purchased limited unique item with serial: ${newSerial}`);
  } else if (!item.is_limited) {
    const getquery = "SELECT * FROM user_inventory WHERE user_id = $1 AND item_id = $2"
    const getvalues = [user.id, item.id]
    const item2 = await executeQuery(getquery, getvalues)
    if (!item2[0]) {
      const insertQuery = "INSERT INTO user_inventory (user_id, item_id) VALUES ($1, $2)";
      const insertValues = [user.id, item.id];
      await executeQuery(insertQuery, insertValues);

      // Deduct the cost from the user's currency
      let updateQuery;
      if (item.currency_type === 1) {
        // Robux
        updateQuery = "UPDATE users SET robux = CAST($1 AS INTEGER) - CAST($2 AS INTEGER) WHERE id = $3";
        const updateValues = [parseInt(user.robux), parseInt(item.price), user.id];
        await executeQuery(updateQuery, updateValues);
      } else if (item.currency_type === 2) {
        // Tix
        updateQuery = "UPDATE users SET tix = CAST($1 AS INTEGER) - CAST($2 AS INTEGER) WHERE id = $3";
        const updateValues = [parseInt(user.tix), parseInt(item.price), user.id];
        await executeQuery(updateQuery, updateValues);
      }
      const owners = await executeQuery(`SELECT * FROM users WHERE username = $1`, [item.creator_name])
      const owner = owners[0]
      let updateQuery2 = "UPDATE users SET robux = CAST($1 AS INTEGER) + CAST($2 AS INTEGER) * 0.7 WHERE id = $3";
      let updateValues2 = [parseInt(owner.robux), parseInt(item.price), owner.id]
      await executeQuery(updateQuery2,updateValues2)
      res.status(200).send("Purchased item");
    }
  }
});
app.get("/Games.aspx", (req, res) => {
  res.redirect("/games")
})
app.get('/api/purchase/:path(*)',rateLimiter, async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.status(200).send("Ok?")
})

app.get("/about", rateLimiter, async (req, res) => {
  const filePath = path.join(__dirname, 'pages', 'about.cshtml');
  fs.readFile(filePath, 'utf8', (err, fileContent) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error reading file');
    }
    res.status(200).send(fileContent)
    // res.send(fileContent);
  });
})

app.get('/catalog/:path', rateLimiter, async (req, res) => {
  try {
    const itemId = req.params.path.replace("/", ""); // Assuming the path contains the item ID or identifier

    // Retrieve the item details from the database based on the provided path or ID
    const itemQuery = "SELECT * FROM items WHERE id = $1";
    const itemValues = [itemId];
    const items = await executeQuery(itemQuery, itemValues);

    if (items.length === 0) {
      // Item not found in the database
      res.status(404).redirect("/request-error?code=404");
      return;
    }

    const item = items[0]; // Assuming the query returns a single item

    // Check if the user is banned
    const userQuery = "SELECT * FROM users WHERE cookie = $1";
    const userValues = [req.cookies?.OLDECS_SECURITY];
    const users = await executeQuery(userQuery, userValues);
    const user = users[0];

    if (user.banned) {
      res.redirect("/auth/not-approved");
      return;
    }

    fs.readFile("Pages/item.cshtml", "utf8", async (err, data) => {
      if (err) {
        console.error("Error reading item.cshtml:", err);
        res.status(500).send("Internal Server Error");
        return;
      }

      // Replace placeholders in the template with dynamic values
      let updatedTemplate = data
        .replace("Oldecs - ITEMNAME", `Oldecs - ${item.name}`)
        .replace("- ITEMNAME", `- ${item.name}`)
        .replace("$ITEMNAME$", item.name)
        .replace("Creator: NAME", `Creator: ${item.creator_name}`)
        .replace("$ITEMDESCRIPTION$", item.description)
        .replace("$ITEMPRICE$", item.price)
        .replace("/api/catalog/$ItemIDHERE$/image", `/api/catalog/${item.id}/image`)
        .replace("$ITEMID$", item.id)
        .replace("$ITEMNAME$", item.name)
        .replace("USERIDHERELUL", user.id)
        .replace("ASSETIDHERELUL", item.id)
        .replace("ASSETIDHERELUL", item.id)
        .replace("USERIDHERELUL", user.id);

      if (item.price === null) {
        updatedTemplate = updatedTemplate.replace(item.price, "Offsale");
        updatedTemplate = updatedTemplate.replace("$ITEMPRICEFR$", "Offsale");
      } else {
        updatedTemplate = updatedTemplate.replace("$ITEMPRICEFR$", item.price);
      }

      if (item.currency_type === 1) {
        updatedTemplate = updatedTemplate.replace("$CURRENCYTYPEHERE$", "Robux");
      } else if (item.currency_type === 2) {
        updatedTemplate = updatedTemplate.replace("$CURRENCYTYPEHERE$", "Tickets");
        updatedTemplate = updatedTemplate.replace("/static/img/robux.png", "/static/img/tix.png");
      } else {
        updatedTemplate = updatedTemplate.replace("$CURRENCYTYPEHERE$", "Unknown");
      }
      updatedTemplate = updatedTemplate.replace("$LIMITEDHERE$", item.is_limited || item.is_limited_unique ? "Limited" : "").replace("$UNIQUEHERE$", item.is_limited_unique ? "Unique" : "");
      if (item.is_limited || item.is_limited_unique) {
        // Replace the "LIMITED" and "UNIQUE" placeholders

        // Retrieve resellers from the resellers table
        const resellersQuery = "SELECT * FROM resellers WHERE item_id = $1"; // Adjust the limit and offset as needed
        const resellersValues = [itemId];
        const resellers = await executeQuery(resellersQuery, resellersValues);

        if (resellers.length > 0) {
          let resellersHTML = `<!--resellers-->`;
          for (const reseller of resellers) {
            if (user.id == reseller.user_id) {
              resellersHTML += `<div>UserID: ${reseller.user_id} -  Price: ${reseller.price} Serial: ${reseller.serial} <button class="unsell-button" data-userid="${reseller.user_id}" data-itemid="${reseller.item_id}" data-serial = "${reseller.serial}">Stop Selling</button></div>`;
            }
            else {
              resellersHTML += `<div>UserID: ${reseller.user_id} -  Price: ${reseller.price} Serial: ${reseller.serial} <button class="buy-button" data-userid="${reseller.user_id}" data-itemid="${reseller.item_id}" data-price="${reseller.price}" data-serial = "${reseller.serial}">Buy</button></div>`;
            }
          }
          resellersHTML += `</div>`;
          updatedTemplate = updatedTemplate.replace("<!--resellers-->", resellersHTML);
        } else {
          updatedTemplate = updatedTemplate.replace("<div class=\"resellers-container\"><h3 class=\"resellers-text\">Resellers</h3></div>", "");
        }
      } else {
        updatedTemplate = updatedTemplate.replace("<div class=\"resellers-container\"><h3 class=\"resellers-text\">Resellers</h3></div>", "");
      }

      res.send(updatedTemplate);
    });
  } catch (error) {
    console.error("Error retrieving item details:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.get("/download", (req, res) => {
  fs.readFile("pages/download.cshtml", "utf8", (err, data) => {
    if (err) {
      console.error("Error reading download:", err);
      res.status(500).send("Internal Server Error");
      return;
    }
    res.send(data)
    })
})
app.post("/api/catalog/unsell/item/:assetid", async (req, res) => {
  try {
    let {userid, serial} = req.query;
    const user = await executeQuery(`SELECT * FROM users WHERE cookie = $1`, [
      req.cookies?.OLDECS_SECURITY,
    ]);
    if (serial == "null") {
      serial = null
    } else {
    }
    console.log(`${userid}, ${serial}`)
    let item
    if (serial) {
      item = await executeQuery(`SELECT * FROM user_inventory WHERE item_id = $1 AND user_id = $2 AND serial = $3`, [
        req.params.assetid, userid, serial
      ]);
    } else {
      item = await executeQuery(`SELECT * FROM user_inventory WHERE item_id = $1 AND user_id = $2`, [
        req.params.assetid, userid
      ]);
    }
    const itemdata = await executeQuery(`SELECT * FROM items WHERE id = $1`, [
      req.params.assetid
    ]);

    if (user.length > 0 && userid == user[0].id && item.length > 0 && (itemdata[0].is_limited)) {
      console.log(`Userid: ${userid} is attempting to stop selling ${req.params.assetid}`)
      const reseller = await executeQuery(
        `SELECT * FROM resellers WHERE user_id = $1 AND item_id = $2`,
        [userid, req.params.assetid]
      );

      if (reseller.length) {
        if (serial != null) {
          await executeQuery(`DELETE FROM resellers WHERE user_id = $1 AND item_id = $2 AND serial = $3`, [userid, req.params.assetid, serial])
        } else {
          await executeQuery(`DELETE FROM resellers WHERE user_id = $1 AND item_id = $2`, [userid, req.params.assetid])
        }


        res.status(200).send("Item removed from sale.");
      } else {
        res.status(400).send("User is not a reseller.");
      }
    } else {
      res.status(400).send("Invalid user ID.");
    }
  } catch (error) {
    console.error("Error processing the request:", error);
    res.status(500).send("Internal server error.");
  }
});
app.post("/api/catalog/buy/item/:assetid", async (req, res) => {
  try {
    const assetId = req.params.assetid;

    const price = req.query.price;
    let serial = req.query.serial;
    if (serial === "null") {
      serial = null;
    }

    // Check if the reseller exists
    const resellerQuery = "SELECT * FROM resellers WHERE item_id = $1";
    const resellerValues = [assetId];
    const reseller = await executeQuery(resellerQuery, resellerValues);

    if (reseller.length === 0) {
      res.status(404).send("Reseller not found");
      return;
    }

    const resellerId = reseller[0].user_id;
    const reseller2 = await executeQuery(`SELECT * FROM users WHERE id = $1`, [resellerId]);
    const users = await executeQuery(`SELECT * FROM users WHERE cookie = $1`, [req.cookies?.OLDECS_SECURITY]);
    const userId = users[0].id;

    // Remove the item from the reseller's inventory
    const resellerSerial2 = await executeQuery(
      "SELECT * FROM user_inventory WHERE user_id = $1 AND item_id = $2",
      [resellerId, assetId]
    );
    // const resellerSerial = resellerSerial2.length > 0 ? resellerSerial2[0].serial : null;
    console.log(resellerId)
    await executeQuery("DELETE FROM user_inventory WHERE user_id = $1 AND item_id = $2", [
      resellerId,
      assetId,
    ]);

    // Add the item to the current user's inventory without specifying a serial
    await executeQuery("INSERT INTO user_inventory (user_id, item_id) SELECT $1, $2", [
      userId,
      assetId,
    ]);

    // Remove the robux from the current user
    const updateUserQuery = "UPDATE users SET robux = CAST($1 AS INTEGER) - CAST($2 AS INTEGER) WHERE id = $3";
    const updateUserValues = [users[0].robux, price, users[0].id];
    console.log(userId)
    console.log(price)
    await executeQuery(updateUserQuery, updateUserValues);

    // Calculate the amount to add to the reseller
    const resellerRobux = price * 0.7;
    const resellerRobuxRounded = resellerRobux.toFixed(2);

    // Add the robux to the reseller
    const updateResellerQuery = "UPDATE users SET robux = CAST($1 AS INTEGER) + CAST($2 AS INTEGER) * 0.7 WHERE id = $3";
    const updateResellerValues = [reseller2[0].robux, price, resellerId];
    await executeQuery(updateResellerQuery, updateResellerValues);
    await executeQuery(`DELETE FROM resellers WHERE user_id = $1 AND item_id = $2`, [resellerId, assetId])

    res.status(200).send("Purchase successful");
  } catch (error) {
    console.error("Error processing purchase:", error);
    res.status(500).send("Internal Server Error");
  }
});
app.post("/api/catalog/sell/item/:assetid", async (req, res) => {
  try {
    const { price, userid } = req.query;
  
    const user = await executeQuery(`SELECT * FROM users WHERE cookie = $1`, [
      req.cookies?.OLDECS_SECURITY,
    ]);
    const item = await executeQuery(`SELECT * FROM user_inventory WHERE item_id = $1 AND user_id = $2`, [
      req.params.assetid, userid
    ]);
    
    const itemdata = await executeQuery(`SELECT * FROM items WHERE id = $1`, [
      req.params.assetid
    ]);

    if (user.length > 0 && userid == user[0].id && item.length > 0 && itemdata[0].is_limited || user.length > 0) {
      const serial = item[0].serial
      console.log(`Userid: ${userid} is attempting to sell ${req.params.assetid} for ${price} robux with serial ${serial}`)
      const reseller = await executeQuery(
        `SELECT * FROM resellers WHERE user_id = $1`,
        [userid]
      );

      if (!reseller.length) {
        await executeQuery(
          `INSERT INTO resellers (user_id, item_id, price, serial) VALUES ($1, $2, $3, $4)`,
          [userid, req.params.assetid, price, serial]
        );

        res.status(200).send("Item added for sale.");
      } else {
        res.status(400).send("User is already a reseller.");
      }
    } else {
      res.status(400).send("Invalid user ID.");
    }
  } catch (error) {
    console.error("Error processing the request:", error);
    res.status(500).send("Internal server error.");
  }
});
app.get("/auth/not-approved", async (req, res) => {
  const query2 = "SELECT * FROM users WHERE cookie = $1";
  const values2 = [req.cookies?.OLDECS_SECURITY];
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.banned) {
    res.status(200).redirect("/home")
    return
  }
  const query = "SELECT * FROM bans WHERE user_id = $1";
  const values = [user.id];
  const bans = await executeQuery(query, values);
  const ban = bans[0]
  fs.readFile("pages/notapproved.cshtml", "utf8", (err, data) => {
    let filec = data.replace(`NOTE`, `${ban.moderator_note}`).replace(`BANNED_AT`, `${ban.banned_at}`).replace("UNBANNED_AT", `${ban.unbanned_at}`)
    res.status(200).send(filec)
  })
})
app.get('/users/:path/inventory', rateLimiter, async (req, res) => {
  try {
    const path = req.params.path;
    const userId = path.split('/')[0];

    // Retrieve items and user details
    const query = `
      SELECT ui.item_id, i.name, ui.serial 
      FROM user_inventory ui 
      INNER JOIN items i ON ui.item_id = i.id 
      WHERE ui.user_id = $1
    `;
    const query2 = `SELECT * FROM users WHERE id = $1`;
    const values2 = [userId]
    // const items = await executeQuery(query, values);
    const users = await executeQuery(query2, values2);
    const values = [userId];
    const results = await executeQuery(query, values);

    let itemsHTML = results.map(result => `
      <a href="/catalog/${result.item_id}" class="item-box">
        <img src="/api/catalog/${result.item_id}/image">
        <div class="title2">${result.name}</div>
        <div class="serial">${result.serial}</div>
      </a>
    `).join('');
    if (results[0]) {
      if (!results[0].is_limited_unique) {
        itemsHTML = results.map(result => `
        <a href="/catalog/${result.item_id}" class="item-box">
          <img src="/api/catalog/${result.item_id}/image">
          <div class="title2">${result.name}</div>
        </a>
      `).join('');
      } else if (results[0].is_limited_unique) {
        itemsHTML = results.map(result => `
        <a href="/catalog/${result.item_id}" class="item-box">
          <img src="/api/catalog/${result.item_id}/image">
          <div class="title2">${result.name}</div>
          <div class="serial">${result.serial}</div>
        </a>
      `).join('');
      }
    }

    // Read the HTML template file
    fs.readFile("pages/inventory.cshtml", "utf8", (err, data) => {
      if (err) {
        console.error("Error reading inventory template:", err);
        res.status(500).send("Internal Server Error");
        return;
      }

      // Replace the placeholders in the template with the generated items HTML and user details
      const renderedPage = data.replace('<div class="items">', `<div class="items">${itemsHTML}`)
                               .replace(/\$USER\$/g, users[0].username)
                               .replace("ROBUXHERE", users[0].robux)
                               .replace("TIXHERE", users[0].tix)
                               .replace("$USERID$", `${users[0].id}`);

      // Send the rendered inventory page
      res.send(renderedPage);
    });
  } catch (error) {
    console.error("Error retrieving item details:", error);
    res.status(500).send("Internal Server Error");
  }
});
app.get('/admin', async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  const query = `SELECT * FROM users`;
  const values = []
  // const items = await executeQuery(query, values);
  const totalusers = await executeQuery(query, values);
  // const totaluser = users[0]
  fs.readFile("pages/admin/dashboard.cshtml", "utf8", (err, data) => {
    let filec = data.replace("$USERSHERE$", `${totalusers.length}`)
    res.status(200).send(filec)
  })
  // res.status(200).send("Coming soon")
})
app.get('/admin/users/:path', async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user2 = users[0]
  if (!user2.admin) {
    res.redirect('/home')
    return
  }
  const query = `SELECT * FROM users WHERE id = $1`;
  const values = [req.params.path]
  // const items = await executeQuery(query, values);
  const users2 = await executeQuery(query, values);
  const user = users2[0]
  fs.readFile("pages/admin/user.cshtml", "utf8", (err, data) => {
    let filec = data.replace("Username", `${user.username}`).replace("Description", `${user.description}`).replace("Created At", `${user.created_at}`).replace("useridherelol", `${user.id}`).replace("useridherelol", `${user.id}`).replace("useridherelol", `${user.id}`).replace("useridherelol", `${user.id}`).replace("USERIDHERELOL", `${user.id}`).replace("Useridherefr", user.id).replace("iddd", user.id)
    res.status(200).send(filec)
  })
})
app.post("/api/admin/users/:path/ban", async (req,res)=>{
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users2 = await executeQuery(query2, values2);
  const user2 = users2[0]
  if (!user2.admin) {
    // res.redirect('/home')
    res.status(400).send("boy dont try to ban if not admin")
    return
  }
  const query = `SELECT * FROM users WHERE id = $1`;
  const values = [req.params.path]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query, values);
  const user = users[0]
  const query3 = `UPDATE users SET banned = $1 WHERE id = $2`;
  const bannedAt = new Date().toISOString();
  const moderatorNote = "Banned by moderator.";
  
  const insertQuery = `INSERT INTO bans (user_id, banned_at, moderator_note) VALUES ($1, $2, $3)`;
  const insertValues = [user.id, bannedAt, moderatorNote];
  await executeQuery(insertQuery, insertValues);
  const values3 = [true, user.id];
  const response = await executeQuery(query3, values3)
  res.status(200).send("complete")
})
app.post("/api/admin/users/:path/adminify", async (req,res)=>{
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users2 = await executeQuery(query2, values2);
  const user2 = users2[0]
  if (!user2.admin || user2.id != 2 && user2.id != 1) {
    // res.redirect('/home')
    res.status(400).send("boy dont try to adminify if you dont have right perms")
    return
  }
  const query = `SELECT * FROM users WHERE id = $1`;
  const values = [req.params.path]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query, values);
  const user = users[0]
  const query3 = `UPDATE users SET admin = $1 WHERE id = $2`;
  const values3 = [true, user.id];
  const response = await executeQuery(query3, values3)
  res.status(200).send("complete")
})
app.post("/api/admin/users/:path/unadminify", async (req,res)=>{
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users2 = await executeQuery(query2, values2);
  const user2 = users2[0]
  if (!user2.admin || user2.id != 2 && user2.id != 1) {
    // res.redirect('/home')
    res.status(400).send("boy dont try to aundminify if you dont have right perms")
    return
  }
  const query = `SELECT * FROM users WHERE id = $1`;
  const values = [req.params.path]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query, values);
  const user = users[0]
  const query3 = `UPDATE users SET admin = $1 WHERE id = $2`;
  const values3 = [false, user.id];
  const response = await executeQuery(query3, values3)
  res.status(200).send("complete")
})
app.post("/api/admin/users/:path/unban", async (req,res)=>{
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users2 = await executeQuery(query2, values2);
  const user2 = users2[0]
  if (!user2.admin) {
    // res.redirect('/home')
    res.status(400).send("boy dont try to unban if not admin")
    return
  }
  const query = `SELECT * FROM users WHERE id = $1`;
  const values = [req.params.path]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query, values);
  const user = users[0]
  const query3 = `UPDATE users SET banned = $1 WHERE id = $2`;
  const values3 = [false, user.id];
  const response = await executeQuery(query3, values3)
  const deleteQuery = `DELETE FROM bans WHERE user_id = $1`;
  const deleteValues = [user.id];
  await executeQuery(deleteQuery, deleteValues);
  res.status(200).send("complete")
})
const usersPerPage = 10; // Number of users to display per page

app.get('/admin/users', async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY];
  const users = await executeQuery(query2, values2);

  if (!users[0].admin) {
    res.redirect('/home');
    return;
  }
  const query = `SELECT * FROM users ORDER BY id ASC`;
  const values = [];
  const allusers = await executeQuery(query, values);
  const page = parseInt(req.query.page) || 1; // Get the requested page number
  const startIndex = (page - 1) * usersPerPage; // Calculate the starting index for the users on the current page
  const endIndex = page * usersPerPage; // Calculate the ending index for the users on the current page

  const usersOnPage = allusers.slice(startIndex, endIndex); // Get the users for the current page

  fs.readFile("pages/admin/users.cshtml", "utf8", (err, data) => {
    if (err) {
      console.error("Error reading users.cshtml:", err);
      res.status(500).send("Internal Server Error");
      return;
    }

    const renderedUsers = usersOnPage.map(user => `
      <tr>
        <td><a href="/admin/users/${user.id}" class="username-link">${user.username}</a></td>
        <td>${user.created_at}</td>
        <td>${user.banned}</td>
        <td>${user.admin}</td>
      </tr>
    `).join('');

    let renderedPage = data.replace("<!-- USERS_DATA -->", renderedUsers);

    const totalPages = Math.ceil(allusers.length / usersPerPage);
    let paginationLinks = '';
    for (let i = 1; i <= totalPages; i++) {
      paginationLinks += `<a href="/admin/users?page=${i}">${i}</a>`;
    }

    renderedPage = renderedPage.replace("<!-- PAGINATION -->", paginationLinks);

    res.status(200).send(renderedPage);
  });
});
app.get('/admin/asset/copy', async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  fs.readFile("pages/admin/copya.cshtml", "utf8", (err, data) => {
    let filec = data
    res.status(200).send(filec)
  })
})
app.get("/admin/asset/edit/:id", async(req, res)=> {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  const query = `SELECT * FROM items WHERE id = $1`;
  const values = [req.params.id]
  // const items = await executeQuery(query, values);
  const items = await executeQuery(query, values);
  const item = items[0]
  fs.readFile("pages/admin/editasset.cshtml", "utf8", (err, data) => {
    let filec = data
    filec = filec.replace("ASSET", `${item.name}`)
    filec = filec.replace("ASSET", `${item.name}`)
    filec = filec.replace("idherelol", item.id)
    filec = filec.replace("/api/catalog/1/image", `/api/catalog/${item.id}/image`)
    // filec = filec.replace()
    res.status(200).send(filec)
  })
})
app.get("/admin/promocode/create", async(req, res)=> {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  const query = `SELECT * FROM items WHERE id = $1`;
  const values = [req.params.id]
  // const items = await executeQuery(query, values);
  const items = await executeQuery(query, values);
  const item = items[0]
  fs.readFile("pages/admin/crpromo.cshtml", "utf8", (err, data) => {
    let filec = data

    // filec = filec.replace()
    res.status(200).send(filec)
  })
})
app.get('/promocodes', (req, res) => {
  fs.readFile("pages/promocode.cshtml", "utf8", (err, data) => {
    let filec = data

    // filec = filec.replace()
    res.status(200).send(filec)
  })
})
app.post('/api/admin/create/promocode', async(req, res) => {
  try {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  const promocode = req.query.promocode;
  const itemIds = req.query.itemIds || null;
  const robux = req.query.robux || 0;
  const tix = req.query.tix || 0;
  const uses = req.query.uses;
  const type = req.query.type;

  // Check if the provided promo code already exists
  const checkQuery = "SELECT * FROM promocodes WHERE promocode = $1";
  const checkValues = [promocode];
  const checkResults = await executeQuery(checkQuery, checkValues);

  if (checkResults.length > 0) {
    return res.status(400).json({ message: "Promo code already exists" });
  }

  // Prepare the query to insert the promo code into the promocodes table
  const insertQuery = `
    INSERT INTO promocodes (promocode, item_ids, robux, tix, uses, type)
    VALUES ($1, $2, $3, $4, $5, $6)
  `;
  const insertValues = [promocode, itemIds, robux, tix, uses, type];

  // Execute the query to insert the promo code
  await executeQuery(insertQuery, insertValues);

  res.status(200).json({ message: "Promo code created successfully" });
} catch (error) {
  console.error(error);
  res.status(500).json({ message: "Error occurred while creating promo code" });
}
})
app.get("/admin/asset/update", async(req, res)=> {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  fs.readFile("pages/admin/edita.cshtml", "utf8", (err, data) => {
    let filec = data
    res.status(200).send(filec)
  })
})
app.get("/admin/game/shutdown", async(req, res)=> {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  fs.readFile("pages/admin/shutdownserver.cshtml", "utf8", (err, data) => {
    let filec = data
    res.status(200).send(filec)
  })
})

app.post("/api/admin/game/shutdown/:id", async(req, res)=> {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  const id = req.params.id
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    res.status(400).send("No.")
    return
  }
  const games = await executeQuery(`SELECT * FROM games WHERE id = $1`, [id]);
  if (!games[0]) {
    return res.redirect("/home")
  }
  await shutdowngameserver(id, req)
  res.status(200).send("Success!")
})
app.post("/api/admin/asset/edit/:assetid", async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY];
  const users = await executeQuery(query2, values2);
  const user = users[0];

  if (!user.admin) {
    res.redirect('/home');
    return;
  }

  const assetId = req.params.assetid;
  const { name, desc, price, lim, limu, max_copies, offsale } = req.query;
  const updateFields = [];

  if (name) {
    updateFields.push(`name = '${name}'`);
  }
  if (desc) {
    updateFields.push(`description = '${desc}'`);
  }
  if (price && offsale !== true) {
    updateFields.push(`price = ${price}`);
  }
  if (lim !== undefined) {
    updateFields.push(`is_limited = ${lim}`);
  }
  if (limu !== undefined) {
    updateFields.push(`is_limited_unique = ${limu}`);
  }
  if (max_copies) {
    updateFields.push(`max_copies = ${max_copies}`);
  }
  if (!max_copies) {
    updateFields.push(`max_copies = null`);
  }
  if (offsale !== false && !price) {
    updateFields.push(`price = null`);
  }

  if (updateFields.length === 0) {
    res.status(400).json({ message: 'No fields to update' });
    return;
  }

  const updateQuery = `UPDATE items SET ${updateFields.join(', ')} WHERE id = ${assetId}`;
  await executeQuery(updateQuery);

  res.status(200).json({ message: assetId.toString() });
});
app.get('/admin/asset/copy/v2', async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  fs.readFile("pages/admin/copyasameid.cshtml", "utf8", (err, data) => {
    let filec = data
    res.status(200).send(filec)
  })
})
app.get('/admin/asset/delete', async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  fs.readFile("pages/admin/deleta.cshtml", "utf8", (err, data) => {
    let filec = data
    res.status(200).send(filec)
  })
})
// const noblox = require('noblox.js')
app.post('/api/admin/delete/asset/:path', async (req, res) => {
  try {
    const assetPath = req.params.path;
    // Delete the asset from the items table
    const deleteItemQuery = "DELETE FROM items WHERE id = $1";
    const deleteItemValues = [assetPath];
    const query2 = `SELECT * FROM users WHERE cookie = $1`;
    const values2 = [req.cookies?.OLDECS_SECURITY]
    // const items = await executeQuery(query, values);
    const users2 = await executeQuery(query2, values2);
    const user2 = users2[0]
    if (!user2.admin) {
      // res.redirect('/home')
      res.status(400).send("boy dont try to ban if not admin")
      return
    }

    await executeQuery(deleteItemQuery, deleteItemValues);
    // Delete the asset from the user_inventory table
    const deleteUserInventoryQuery = "DELETE FROM user_inventory WHERE item_id = $1";
    const deleteUserInventoryValues = [assetPath];
    await executeQuery(deleteUserInventoryQuery, deleteUserInventoryValues);

    // Delete the asset file from the Assets folder
    const filePath = path.join(__dirname, 'Assets', `${assetPath}`);
    fs.unlinkSync(filePath);

    // Delete the corresponding icon file from the Icons folder
    const iconPath = path.join(__dirname, 'Icons', `${assetPath}.png`);
    fs.unlinkSync(iconPath);

    res.status(200).json({ message: 'Asset deleted successfully!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error occurred while deleting asset.' });
  }
});
app.post('/api/admin/copy/asset/:path', async (req, res) => {
  try {
    const assetPath = req.params.path;
    const cr = req.query.creator

    // Fetch item details using noblox.js
    const body = {
      "items": [
        {
          "itemType": "Asset",
          "id": assetPath
        }
      ]
    };
    const query2 = `SELECT * FROM users WHERE cookie = $1`;
    const values2 = [req.cookies?.OLDECS_SECURITY]
    // const items = await executeQuery(query, values);
    const users2 = await executeQuery(query2, values2);
    const user2 = users2[0]
    if (!user2.admin) {
      // res.redirect('/home')
      res.status(400).send("boy dont try to copy asset if not admin")
      return
    }

    const failedResponse = await axiosClient.post("https://catalog.roblox.com/v1/catalog/items/details", body, { validateStatus: false });
    const csrfToken = failedResponse.headers['x-csrf-token']; 

    // Fetch the item details with the CSRF token included in the request headers
    const itemDetailsResponse = await axiosClient.post("https://catalog.roblox.com/v1/catalog/items/details", body, {
      headers: { 'x-csrf-token': csrfToken }
    });
    // console.log(itemDetailsResponse.data)
    const itemDetails = itemDetailsResponse.data;
    // console.log(itemDetails)
    // console.log(itemDetailsResponse)
    // Fetch the asset from asset delivery
    const assetUrl = `https://assetdelivery.roblox.com/v1/asset?id=${assetPath}`;
    const assetResponse = await axiosClient.get(assetUrl, { responseType: 'arraybuffer' });
    
    // Save the asset file to the Assets folder

    // Insert asset details into the items table
    const countQuery = "SELECT * FROM items";
    const countQuery2 = "SELECT * FROM games";
    const users = await executeQuery("SELECT id FROM users WHERE username = $1", [cr ? cr : "ROBLOX"]);
    const user = users[0]
    const countResult = await executeQuery(countQuery);
    const countResult2 = await executeQuery(countQuery2);
    const itemCount = countResult.length;
    const gameCount = countResult2.length;
    
    const maxId = itemCount + gameCount + 1 || 1;
    const filePath = path.join(__dirname, 'Assets', `${maxId}`);
    fs.writeFileSync(filePath, assetResponse.data);
    // console.log(itemDetails)
    console.log(itemDetails.data[0])
    const newItem = {
      id: maxId,
      asset_type: itemDetails.data[0].assetType,
      name: itemDetails.data[0]["name"],
      creator_name: cr ? cr : "ROBLOX",
      description: itemDetails.data[0]["description"],
      currency_type: 1,
      is_limited_unique: false,
      is_limited: false,
      creator_id: cr ? user.id : 1,
      // max_copies: itemDetails.stock,
    };

    const insertQuery = `
      INSERT INTO items (id, name, creator_name, description, currency_type, asset_type, creator_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `;
    const insertValues = [
      newItem.id,
      newItem.name,
      newItem.creator_name,
      newItem.description,
      newItem.currency_type,
      newItem.asset_type,
      newItem.creator_id
    ];

    await executeQuery(insertQuery, insertValues);
    const insertUserInventoryQuery = `
    INSERT INTO user_inventory (item_id, user_id, serial)
    VALUES ($1, $2, $3)
  `;
  const insertUserInventoryValues = [
    maxId, // Replace with the appropriate value for item_id
    user.id, // Replace with the appropriate value for user_id
    null // Replace with the appropriate value for serial
  ];

  await executeQuery(insertUserInventoryQuery, insertUserInventoryValues);
    if (newItem.asset_type == 19 || newItem.asset_type == 8 || newItem.asset_type == 41) {
    axiosClient.post(`https://www.oldecs.com/render/asset?id=${maxId}`)
    } else if (newItem.asset_type == 18){
      axiosClient.post(`https://www.oldecs.com/render/face?id=${maxId}`)
    } else if (newItem.asset_type == 12) {
      axiosClient.post(`https://www.oldecs.com/render/pants?id=${maxId}`)
    } else if (newItem.asset_type == 11) {
      axiosClient.post(`https://www.oldecs.com/render/shirt?id=${maxId}`)
    } else if (newItem.asset_type == 2) {
      axiosClient.post(`https://www.oldecs.com/render/tshirt?id=${maxId}`)
    }

    res.status(200).json({ message: `${maxId.toString()}` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error occurred while copying asset.' });
  }
});
app.post("/api/redeem/promocode", async (req, res) => {
  try {
    const promocode = req.query.promocode;
    const userId = req.query.userid;

    // Query the promocodes table to fetch the details of the provided promo code
    const query = "SELECT * FROM promocodes WHERE promocode = $1";
    const values = [promocode];
    const results = await executeQuery(query, values);

    // Check if the promo code exists and is still valid
    if (results.length === 0) {
      return res.status(400).json({ message: "Invalid promo code" });
    }

    const promo = results[0];
    if (promo.uses === 0) {
      return res.status(400).json({ message: "Promo code has been fully redeemed" });
    }

    // Process the redemption logic based on the promo code type
    if (promo.type === "item") {
      // Handle item redemption logic
      const itemIds = promo.item_ids.split(","); // Assuming item_ids is stored as a comma-separated string

      // Check if the user already has any of the redeemed items in their inventory
      const existingItemsQuery = "SELECT item_id FROM user_inventory WHERE user_id = $1 AND item_id = ANY($2)";
      const existingItemsValues = [userId, itemIds];
      const existingItemsResults = await executeQuery(existingItemsQuery, existingItemsValues);

      const existingItemIds = existingItemsResults.map(result => result.item_id);

      // Filter out the items that the user already has
      const newItems = itemIds.filter(itemId => !existingItemIds.includes(itemId));

      // Update the user's inventory with the redeemed items if they don't already have them
      for (const itemId of newItems) {
        const insertQuery = "INSERT INTO user_inventory (user_id, item_id, serial) VALUES ($1, $2, $3)";
        const insertValues = [userId, itemId, 0, null];
        await executeQuery(insertQuery, insertValues);
      }
    } else if (promo.type === "currency") {
      // Handle currency redemption logic (e.g., robux or tix)
      let increment = 0;

      if (promo.robux) {
        // Update the user's robux balance
        increment += promo.robux;
        // Example: Update the user's robux balance
        const updateQuery = "UPDATE users SET robux = robux + $1 WHERE id = $2";
        const updateValues = [promo.robux, userId];
        await executeQuery(updateQuery, updateValues);
      }

      if (promo.tix) {
        // Update the user's tix balance
        increment += promo.tix;
        // Example: Update the user's tix balance
        const updateQuery = "UPDATE users SET tix = tix + $1 WHERE id = $2";
        const updateValues = [promo.tix, userId];
        await executeQuery(updateQuery, updateValues);
      }

      // Add other currency types if applicable

      if (increment === 0) {
        return res.status(400).json({ message: "Invalid promo code" });
      }
    } else {
      // Invalid promo code type
      return res.status(400).json({ message: "Invalid promo code type" });
    }

    // Update the remaining uses of the promo code
    const updateQuery = "UPDATE promocodes SET uses = uses - 1 WHERE promocode = $1";
    const updateValues = [promocode];
    await executeQuery(updateQuery, updateValues);

    res.status(200).json({ message: "Promo code redeemed successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error occurred while redeeming promo code" });
  }
});
app.post('/api/admin/copy/asset/v2/:path', async (req, res) => {
  try {
    const assetPath = req.params.path;
    const sameid = req.query.sameid;

    // Fetch item details using noblox.js
    // const body = {
    //   "items": [
    //     {
    //       "itemType": "Asset",
    //       "id": assetPath
    //     }
    //   ]
    // };
    const query2 = `SELECT * FROM users WHERE cookie = $1`;
    const values2 = [req.cookies?.OLDECS_SECURITY]
    // const items = await executeQuery(query, values);
    const users2 = await executeQuery(query2, values2);
    const user2 = users2[0]
    if (!user2.admin) {
      // res.redirect('/home')
      res.status(400).send("boy dont try to copy asset if not admin")
      return
    }

    // const failedResponse = await axiosClient.post("https://catalog.roblox.com/v1/catalog/items/details", body, { validateStatus: false });
    // const csrfToken = failedResponse.headers['x-csrf-token']; 

    // Fetch the item details with the CSRF token included in the request headers
    // const itemDetailsResponse = await axiosClient.post("https://catalog.roblox.com/v1/catalog/items/details", body, {
      // headers: { 'x-csrf-token': csrfToken }
    // });
    // console.log(itemDetailsResponse.data)
    // const itemDetails = itemDetailsResponse.data;
    // console.log(itemDetails)
    // console.log(itemDetailsResponse)
    // Fetch the asset from asset delivery
    const assetUrl = `https://assetdelivery.roblox.com/v1/asset?id=${assetPath}`;
    const assetResponse = await axiosClient.get(assetUrl, { responseType: 'arraybuffer' });
    
    // Save the asset file to the Assets folder

    // Insert asset details into the items table
    const countQuery = "SELECT * FROM items";
    const countResult = await executeQuery(countQuery);
    const itemCount = countResult.length;
    
    const maxId = assetPath;
    const filePath = path.join(__dirname, 'Assets', `${maxId}`);
    fs.writeFileSync(filePath, assetResponse.data);
    // console.log(itemDetails)
    // console.log(itemDetails.data[0])
    const newItem = {
      id: assetPath,
      asset_type: -1,
      name: `Asset${assetPath}`,
      creator_name: "ROBLOX",
      description: "ConversionV2.0",
      currency_type: 1,
      is_limited_unique: false,
      is_limited: false,
      // max_copies: itemDetails.stock,
    };

    const insertQuery = `
      INSERT INTO items (id, name, creator_name, description, currency_type, asset_type)
      VALUES ($1, $2, $3, $4, $5, $6)
    `;
    const insertValues = [
      newItem.id,
      newItem.name,
      newItem.creator_name,
      newItem.description,
      newItem.currency_type,
      newItem.asset_type
    ];

    await executeQuery(insertQuery, insertValues);
    const insertUserInventoryQuery = `
    INSERT INTO user_inventory (item_id, user_id, selling_for, serial)
    VALUES ($1, $2, $3, $4)
  `;
  const insertUserInventoryValues = [
    maxId, // Replace with the appropriate value for item_id
    1, // Replace with the appropriate value for user_id
    0, // Replace with the appropriate value for selling_for
    null // Replace with the appropriate value for serial
  ];

  // await executeQuery(insertUserInventoryQuery, insertUserInventoryValues);
    // if (newItem.asset_type != 18) {
    // axiosClient.post(`https://www.oldecs.com/render/asset?id=${maxId}`)
    // } else {
    //   axiosClient.post(`https://www.oldecs.com/render/face?id=${maxId}`)
    // }

    res.status(200).json({ message: 'Asset copied successfully!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error occurred while copying asset.' });
  }
});
app.post("/render/asset", async (req, res) => {
  const assetid = req.query.id
  let scriptToSend = `${fs.readFileSync(`scripts/asset.lua`)}`
  scriptToSend = scriptToSend.replace("ASSET_ID", `${assetid}`)
  const xml = `<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <OpenJobEx xmlns="http://roblox.com/">
        <job>
            <id>renderasset${assetid}</id>
            <category>0</category>
            <cores>1</cores>
            <expirationInSeconds>3</expirationInSeconds>
        </job>
        <script>
            <name>GameStart</name>
            <script>
            <![CDATA[
            ${scriptToSend}
            ]]>
            </script>
        </script>
    </OpenJobEx>
  </soap:Body>
  </soap:Envelope>`
  axiosClient.post("http://127.0.0.1:64990",xml).then(async(data2) => {
    const { DOMParser } = require('xmldom');
    const parser = new DOMParser()
    const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
    const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
    // console.log(value)
    console.log(`Writing ${assetid}.png`)
    await fs.writeFileSync(`C:/project/Icons/${assetid}.png`, Buffer.from(value, 'base64'))
    res.status(200).sendFile(`C:/project/Icons/${assetid}.png`)
  })
})
app.post("/render/game", async (req, res) => {
  const assetid2 = req.query.id
  const game = await executeQuery(`SELECT * FROM games WHERE id = $1`, [assetid2])
  const assetid = game[0].asset_id
  let scriptToSend = `${fs.readFileSync(`scripts/game.lua`)}`
  scriptToSend = scriptToSend.replace("ASSET_ID", `${assetid}`)
  const xml = `<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <OpenJobEx xmlns="http://roblox.com/">
        <job>
            <id>renderasset${assetid}</id>
            <category>0</category>
            <cores>1</cores>
            <expirationInSeconds>3</expirationInSeconds>
        </job>
        <script>
            <name>GameStart</name>
            <script>
            <![CDATA[
            ${scriptToSend}
            ]]>
            </script>
        </script>
    </OpenJobEx>
  </soap:Body>
  </soap:Envelope>`
  axiosClient.post("http://127.0.0.1:64990",xml).then(async(data2) => {
    const { DOMParser } = require('xmldom');
    const parser = new DOMParser()
    const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
    const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
    // console.log(value)
    console.log(`Writing ${assetid}.png`)
    await fs.writeFileSync(`C:/project/Games/${assetid2}.png`, Buffer.from(value, 'base64'))
    res.status(200).sendFile(`C:/project/Games/${assetid2}.png`)
  })
})
app.post("/render/face", async (req, res) => {
  const assetid = req.query.id
  let scriptToSend = `${fs.readFileSync(`scripts/face.lua`)}`
  scriptToSend = scriptToSend.replace("ASSET_ID", `${assetid}`)
  const xml = `<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <OpenJobEx xmlns="http://roblox.com/">
        <job>
            <id>renderasset${assetid}</id>
            <category>0</category>
            <cores>1</cores>
            <expirationInSeconds>10</expirationInSeconds>
        </job>
        <script>
            <name>GameStart</name>
            <script>
            <![CDATA[
            ${scriptToSend}
            ]]>
            </script>
        </script>
    </OpenJobEx>
  </soap:Body>
  </soap:Envelope>`
  axiosClient.post("http://127.0.0.1:64990",xml).then(async(data2) => {
    const { DOMParser } = require('xmldom');
    const parser = new DOMParser()
    const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
    const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
    // console.log(value)
    console.log(`Writing ${assetid}.png`)
    await fs.writeFileSync(`C:/project/Icons/${assetid}.png`, Buffer.from(value, 'base64'))
    res.status(200).sendFile(`C:/project/Icons/${assetid}.png`)
  })
})
app.post("/render/shirt", async (req, res) => {
  const assetid = req.query.id
  let scriptToSend = `${fs.readFileSync(`scripts/shirt.lua`)}`
  scriptToSend = scriptToSend.replace("ASSET_ID", `${assetid}`)
  const xml = `<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <OpenJobEx xmlns="http://roblox.com/">
        <job>
            <id>renderasset${assetid}</id>
            <category>0</category>
            <cores>1</cores>
            <expirationInSeconds>10</expirationInSeconds>
        </job>
        <script>
            <name>GameStart</name>
            <script>
            <![CDATA[
            ${scriptToSend}
            ]]>
            </script>
        </script>
    </OpenJobEx>
  </soap:Body>
  </soap:Envelope>`
  axiosClient.post("http://127.0.0.1:64990",xml).then(async(data2) => {
    const { DOMParser } = require('xmldom');
    const parser = new DOMParser()
    const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
    const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
    // console.log(value)
    console.log(`Writing ${assetid}.png`)
    await fs.writeFileSync(`C:/project/Icons/${assetid}.png`, Buffer.from(value, 'base64'))
    res.status(200).sendFile(`C:/project/Icons/${assetid}.png`)
  })
})
const sharp = require('sharp')
const Jimp = require('jimp');

app.post("/render/tshirt", async (req, res) => {
  const assetid = req.query.id
  let scriptToSend = `${fs.readFileSync(`scripts/tshirt.lua`)}`
  scriptToSend = scriptToSend.replace("ASSET_ID", `${assetid}`)
  const xml = `<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <OpenJobEx xmlns="http://roblox.com/">
        <job>
            <id>renderasset${assetid}</id>
            <category>0</category>
            <cores>1</cores>
            <expirationInSeconds>10</expirationInSeconds>
        </job>
        <script>
            <name>GameStart</name>
            <script>
            <![CDATA[
            ${scriptToSend}
            ]]>
            </script>
        </script>
    </OpenJobEx>
  </soap:Body>
  </soap:Envelope>`
  axiosClient.post("http://127.0.0.1:64990", xml).then(async (data2) => {
    const { DOMParser } = require('xmldom');
    const parser = new DOMParser();
  
    const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
    const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
  
    const tempImagePath = `C:/project/temp/${assetid}.png`;
  
    // Save the temporary image
    fs.writeFileSync(tempImagePath, Buffer.from(value, 'base64'));
  
    // Perform background blending
    await blendImages(``, tempImagePath, assetid);
  
    console.log(`Writing ${assetid}.png`);
    res.status(200).sendFile(`C:/project/Icons/${assetid}.png`);
  });
  
})
const teeshirttemplatePath = fs.readFileSync("C:/project/TeeShirtTemplate.png")
async function blendImages(backgroundPath, foregroundPath, assetid) {
  try {
    const teeshirttemplate = await Jimp.read(teeshirttemplatePath);
    const foreground = await Jimp.read(foregroundPath);

    // Resize foreground image if necessary
    if (foreground.bitmap.width > teeshirttemplate.bitmap.width || foreground.bitmap.height > teeshirttemplate.bitmap.height) {
      foreground.resize(teeshirttemplate.bitmap.width, teeshirttemplate.bitmap.height);
    }

    // Calculate the coordinates to place the foreground image in the middle
    const x = Math.floor((teeshirttemplate.bitmap.width - foreground.bitmap.width) / 2);
    const y = Math.floor((teeshirttemplate.bitmap.height - foreground.bitmap.height) / 2) + 50; // Adjust the offset as needed

    // Create a new image with the same dimensions as the teeshirttemplate
    const blendedImage = new Jimp(teeshirttemplate.bitmap.width, teeshirttemplate.bitmap.height);

    // Composite the teeshirttemplate onto the blended image
    blendedImage.composite(teeshirttemplate, 0, 0);

    // Composite the foreground image on top of the blended image at the calculated coordinates
    blendedImage.composite(foreground, x, y);

    // Save the blended image
    const blendImagePath = `C:/project/Icons/${assetid}.png`;
    await blendedImage.writeAsync(blendImagePath);
  } catch (error) {
    console.error('An error occurred:', error);
  }
}
app.post("/render/pants", async (req, res) => {
  const assetid = req.query.id
  let scriptToSend = `${fs.readFileSync(`scripts/pants.lua`)}`
  scriptToSend = scriptToSend.replace("ASSET_ID", `${assetid}`)
  const xml = `<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <OpenJobEx xmlns="http://roblox.com/">
        <job>
            <id>renderasset${assetid}</id>
            <category>0</category>
            <cores>1</cores>
            <expirationInSeconds>10</expirationInSeconds>
        </job>
        <script>
            <name>GameStart</name>
            <script>
            <![CDATA[
            ${scriptToSend}
            ]]>
            </script>
        </script>
    </OpenJobEx>
  </soap:Body>
  </soap:Envelope>`
  axiosClient.post("http://127.0.0.1:64990",xml).then(async(data2) => {
    const { DOMParser } = require('xmldom');
    const parser = new DOMParser()
    const xmlDoc = parser.parseFromString(data2.data, 'text/xml');
    const value = xmlDoc.getElementsByTagName('ns1:value')[0].textContent;
    // console.log(value)
    console.log(`Writing ${assetid}.png`)
    await fs.writeFileSync(`C:/project/Icons/${assetid}.png`, Buffer.from(value, 'base64'))
    res.status(200).sendFile(`C:/project/Icons/${assetid}.png`)
  })
})
app.get('/admin/asset/create', async (req, res) => {
  const query2 = `SELECT * FROM users WHERE cookie = $1`;
  const values2 = [req.cookies?.OLDECS_SECURITY]
  // const items = await executeQuery(query, values);
  const users = await executeQuery(query2, values2);
  const user = users[0]
  if (!user.admin) {
    res.redirect('/home')
    return
  }
  res.status(200).send("Coming soon")
})
app.get('/ownership/hasasset/:path(*)', rateLimiter, (req, res) => {
  res.send('true');
});
// Sign up page
app.get("/joinscript", rateLimiter, async (req, res) => {
  const cookie = req.cookies?.OLDECS_SECURITY
  const ticket = await generateTicket(100, cookie)
  const isguest = req.query.guest
  const id = req.query.placeid
  const port = req.query.port
  if (!port || !id) {
    // res.status(400).send("Please follow the instructions.")
    // return;
  }
  res.set('Content-Type', 'application/json');
  if (ticket && !isguest || ticket && isguest == 0) {
    res.send(`-a https://www.oldecs.com/Login/Negotiate.ashx -j "https://www.oldecs.com/Game/Placelauncher2018.ashx?t=${ticket}&placeid=${id}" -t ${ticket}`)
  } else if (!ticket) {
    res.send(`-a "https://www.oldecs.com/Login/Negotiate.ashx" -j "https://www.oldecs.com/Game/Placelauncher2018.ashx?placeid=${id}" -t ""`)
  } else if (isguest == 1) {
    res.send(`-a "https://www.oldecs.com/Login/Negotiate.ashx" -j "https://www.oldecs.com/Game/Placelauncher2018.ashx?placeid=${id}&port=${port}" -t ""`)
  }
})
app.get("/", rateLimiter, async (req, res) => {
  if (req.cookies?.OLDECS_SECURITY) {
    res.redirect("/home");
    return;
  }

  const username = req.query.username || "";
  const password = req.query.password || "";
  console.log(`Signing up using: username ${username}`);
  // if (req)
  if (username && password) {
    try {
      const res2 = await validateTurnstileResponse(req)
    
      if (!res2) {
        return res.redirect("/")
      }
      const whitespaceRegex = /\s/;
      const htmlRegex = /<[^>]+>/g;
      if (whitespaceRegex.test(username) || whitespaceRegex.test(password)) {
        // Handle case when username or password contains whitespace
        // For example, display an error message or prevent further execution
        // console.log("Username or password cannot contain whitespace.");
        res.status(400).send("Bad request, trying to make a username with spaces.")
        return;
      }    
      if (htmlRegex.test(username) || htmlRegex.test(password)) {
        // Handle case when username or password contains HTML code
        // For example, display an error message or prevent further execution
        res.status(400).send("Bad request, trying to make a username with html code.")
        return;
      }
      // Database operations to create a new user
      const highestIdQuery = "SELECT MAX(id) AS maxId FROM users";
      const allusersquery = `SELECT * FROM users WHERE username ILIKE $1`;
      const valuesall = [username]; // Assuming 'username' is the variable containing the username to check
      const resultall = await executeQuery(allusersquery, valuesall);
      // if (resultall) {
        if (resultall[0]) {
        res.status(400).send("Bro what?")
        return
      }
      let username2 = username.toString()
      if (username2.includes("nigger") || username2.includes("n1gger") ||username2.includes("nigga") || username2.includes("n1gga")) {
        return res.status(400).send("what.")
      }
      const highestIdResult = await executeQuery(highestIdQuery);
      // console.log(highestIdResult[0].maxid)
      const newId = highestIdResult[0].maxid + 1
      let randomNumber = Math.floor(Math.random() * (951 - 500) + 500);
      const cookie = generateCookieString(randomNumber);
      console.log(`generating a cookie in length: ${randomNumber}`)
      const currentDate = new Date()
      const formattedDate = currentDate.toLocaleDateString();
      const formattedTime = currentDate.toLocaleTimeString();
      // console.log(`Current date: ${formattedDate} ${formattedTime}`)
      const query =
        "INSERT INTO users (id, username, password, cookie, membership, robux, tix, description, banned, created_at, admin) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
        const hashedPassword = await argon2.hash(password); // Generate a salt and hash the password
        // const hashedCookie = await bcrypt.hash(cookie, 10);
        const values = [newId, username, hashedPassword, cookie, "None", 100, 0, "", false, `${formattedDate} ${formattedTime}`, false];
      await executeQuery(query, values);
      axiosClient.post(`https://www.oldecs.com/render/avatar?id=${newId}`)

      const cookieOptions = {
        expires: new Date(Date.now() + 100 * 24 * 60 * 60 * 1000), // Expires in 100 days
        secure: true,
        httpOnly: true,
      };

      // console.log(`Cookie: ${cookie}`);

      res.cookie("OLDECS_SECURITY", cookie, cookieOptions);
      res.redirect("/home");
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).send("Internal Server Error");
    }
    return;
  }

  fs.readFile("Pages/signup.cshtml", "utf8", (err, data) => {
    if (err) {
      console.error("Error reading signup.cshtml:", err);
      res.status(500).send("Internal Server Error");
      return;
    }

    res.send(data);
  });
});
// Home page

app.get("/home", rateLimiter, async (req, res) => {
  const cookieValue = req.cookies.OLDECS_SECURITY;
  // console.log(cookieValue)
  // res.cookie.g
  // console.log(req.cookies)
  if (!cookieValue) {
    res.redirect("/login");
    return;
  }

  try {
    const query = "SELECT * FROM users WHERE cookie = $1";
    const values = [cookieValue];
    const result = await executeQuery(query, values);
    const user = result[0];

    if (!user) {
      res.redirect("/login");
      return;
    }
    if (user.banned == true) {
      res.redirect("/auth/not-approved");
      return;
    }
    let fileContent = ""
    fs.readFile("pages/home.cshtml",'utf8', (err, filec) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error reading file');
      }
  
      // Do something with the file content
      fileContent = filec
      // console.log(`${user.username}'s (id: ${user.id}) ip: ${req.headers['x-forwarded-for'] || req.connection.remoteAddress}`)
      let updatedContent = fileContent.replace("Username", user.username);
      updatedContent = updatedContent.replace("/USERIDHERE", `/${user.id}`)
      if (user.admin) {
        updatedContent = updatedContent.replace("Membership", "Administrator");
      }  else if (user.membership == "OutrageousBuildersClub") {
        updatedContent = updatedContent.replace('Membership', `OBC` || '');
      } else if (user.membership == "BuildersClub") {
        updatedContent = updatedContent.replace('Membership', `BC` || '');
      } else if (user.membership == "TurboBuildersClub") {
        updatedContent = updatedContent.replace('Membership', `TBC` || '');
      } else {
        updatedContent = updatedContent.replace('(Membership)', `` || '');
      }
      updatedContent = updatedContent.replace("ROBUXHERE", user.robux.toString());
      updatedContent = updatedContent.replace("TIXHERE", user.tix.toString()).replace("$USERID$", `${user.id}`);
  
      res.send(updatedContent);
    });
  } catch (error) {
    console.error("Error retrieving user information:", error);
    res.status(500).send("Internal Server Error");
  }
});
const bcrypt = require('bcrypt');
const { charsets } = require('mime');
// Login page
app.post('/api/add-friend', async (req, res) => {
  try {
    const { senderId, receiverId } = req.query;

    // Insert the friend request into the friend_requests table
    const friendRequestQuery = 'INSERT INTO friend_requests (sender_id, receiver_id) VALUES ($1, $2)';
    await executeQuery(friendRequestQuery, [senderId, receiverId]);
    const friendrequestcheckQuery = 'SELECT * FROM friend_requests WHERE sender_id = $1 AND receiver_id = $2';
    const friendResult = await executeQuery(friendrequestcheckQuery, [senderId, receiverId])
    const friendcheckQuery = 'SELECT * FROM friend_requests WHERE user_id = $1 AND friend_id = $2';
    const friendResult2 = await executeQuery(friendcheckQuery, [senderId, receiverId])
    if (friendResult[0] || friendResult2[0]) {
      return res.status(400).send("You already sent a friend request to this user!")
    }

    // Send a response indicating successful friend request sent
    res.status(200).json({ message: 'Friend request sent successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while sending the friend request' });
  }
});
app.get("/login", rateLimiter, async (req, res) => {
  if (req.cookies?.OLDECS_SECURITY) {
    res.redirect("/home");
    return;
  }

  const username = req.query.username || "";
  const password = req.query.password || "";
  console.log(`Logging in using: username ${username}`);

  if (username && password) {
    try {
      // const body = await req.formDat();
      // console.log(req.query)
      const res2 = await validateTurnstileResponse(req)
      // console.log(res2)
      if (!res2) {
        return res.redirect("/login")
      }
      // Database operations to validate user credentials
      const query = "SELECT * FROM users WHERE username = $1";
      const values = [username];
      const users = await executeQuery(query, values);

      if (users.length === 0) {
        console.log("User not found");
        res.redirect("/login");
        return;
      }

      const user = users[0];

      const passwordMatch = await argon2.verify(user.password, password);

      if (!passwordMatch) {

        console.log("Incorrect password");
        res.redirect("/login");
        return;
      }

      const cookieOptions = {
        expires: new Date(Date.now() + 100 * 24 * 60 * 60 * 1000), // Expires in 100 days
        secure: true,
        httpOnly: true,
      };

      const cookieMatch = user.cookie;
      if (!cookieMatch) {
        res.send("Invalid cookie")
        res.redirect("/login")
      return
      }

      res.cookie("OLDECS_SECURITY", user.cookie, cookieOptions);
      res.redirect("/home");
    } catch (error) {
      console.error("Error validating user:", error);
      res.status(500).send("Internal Server Error");
    }
    return;
  }

  fs.readFile("Pages/login.cshtml", "utf8", (err, data) => {
    if (err) {
      console.error("Error reading login.cshtml:", err);
      res.status(500).send("Internal Server Error");
      return;
    }

    res.send(data);
  });
});
app.get('/Asset/BodyColors.ashx', async(req, res) => {
  const userId = req.query.userId || req.query.userid;

  // Fetch the user's body colors from the user_wearing table
  const query = "SELECT * FROM user_bodycolors WHERE user_id = $1";
  const values = [userId];
  const result = await executeQuery(query, values);
  const userWearing = result[0];

  if (!userWearing) {
    // User not found, use default body colors (user ID 2)
    res.contentType('application/xml');
    const defaultColors = `<roblox xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.roblox.com/roblox.xsd" version="4">
      <External>null</External>
      <External>nil</External>
      <Item class="BodyColors">
        <Properties>
          <int name="HeadColor">1</int>
          <int name="LeftArmColor">1</int>
          <int name="LeftLegColor">1001</int>
          <string name="Name">Body Colors</string>
          <int name="RightArmColor">1</int>
          <int name="RightLegColor">1001</int>
          <int name="TorsoColor">1003</int>
          <bool name="archivable">true</bool>
        </Properties>
      </Item>
    </roblox>`;
    res.send(defaultColors);
    return;
  }

  // Extract the body color values from userWearing
  const {
    head_color,
    left_arm_color,
    left_leg_color,
    right_arm_color,
    right_leg_color,
    torso_color,
  } = userWearing;

  // Construct the body colors XML with the actual color values
  const bodyColors = `<roblox xmlns:xmime="http://www.w3.org/2005/05/xmlmime" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.roblox.com/roblox.xsd" version="4">
    <External>null</External>
    <External>nil</External>
    <Item class="BodyColors">
      <Properties>
        <int name="HeadColor">${head_color}</int>
        <int name="LeftArmColor">${left_arm_color}</int>
        <int name="LeftLegColor">${left_leg_color}</int>
        <string name="Name">Body Colors</string>
        <int name="RightArmColor">${right_arm_color}</int>
        <int name="RightLegColor">${right_leg_color}</int>
        <int name="TorsoColor">${torso_color}</int>
        <bool name="archivable">true</bool>
      </Properties>
    </Item>
  </roblox>`;

  res.contentType('application/xml');
  res.send(bodyColors);
});
process.on('uncaughtException', (e) => {
  console.log(e)
})
app.get("/currency/balance", (req, res ) => {
  console.log(req.body)
  console.log(req.query)
  // console.log(req.query)
  res.status(200).json({"robux": 25000000, "tickets": 1349})
})
// app.get('*', function(req, res){
//   // console.log(req.url)
//   // console.log(req.query)
//   // console.log(req.path)
//   // console.log(req)
//   // console.log(req.query)
//   // console.log(req.params)
//   // console.log(req.headers)
//   res.redirect("/request-error?code=404");
// })
app.post("/marketplace/validatepurchase", async(req,res)=> {
  // console.log(req.url)
  console.log("MARKETPLACE VALIDATE PURCHASE BELOW")
  console.log(`QUERY:`)
  console.log(req.query)
  console.log(`BODY:`)
  console.log(req.body)
  console.log("END")
  const user_id = req.query.userid
  console.log(user_id)
  // console.log(resp)
  const receipt = await executeQuery(`SELECT * FROM receipts WHERE receipt = $1`, [req.query.receipt])
  if (receipt[0]) {
    await executeQuery(`UPDATE receipts SET user_id = ${user_id} WHERE receipt = $1`, [receipt[0].receipt])
  }
  // console.log(receipt[0])
  if (receipt[0]) {
  res.status(200).json({"placeId": receipt[0].placeid, "productId": receipt[0].productid, "playerId": receipt[0].user_id})
  } else {
    res.status(404).json({"data":[]})
  }
})
app.post("/marketplace/submitpurchase", async(req,res)=> {
  // console.log(req.url)
  // console.log(req.query)
  const receipt = generateCookieString(100).toUpperCase();
  console.log(req.body)
  console.log(req.query)
  const user_id = req.query.userId
  res.status(200).json({"receipt": receipt})
  await executeQuery(`INSERT INTO receipts (receipt, user_id,productid,expectedprice,placeid) VALUES ($1, $2, $3, $4, $5)`, [receipt, user_id, req.body.productId, req.body.expectedUnitPrice,req.body.placeId])
})
app.post("/game/load-place-info",(req,res)=>{
  // console.log(req.body)
  const placeid = req.headers["roblox-place-id"]
  // console.log(req.headers)
  // console.log(req.headers["roblox-place-id"])
  res.status(200).type("application/json").send(`{"CreatorId":2,"CreatorType":"User", "PlaceVersion":1, "GameId":${placeid},"IsRobloxPlace":true}`)
})
app.post("/game/validate-machine",(req,res)=>{
  res.json({"success":true})
})
app.get('*', function(req, res){
  console.log(req.url)
  console.log(req.query)
  // console.log(req.path)
  console.log(req.body)
  // console.log(req.query)
  // console.log(req.params)
  // console.log(req.headers)
  res.status(404).redirect("/request-error?code=404");
})
app.post("*", (req,res) => {
// console.log(req.headers)
  console.log(req.url)
  console.log(req.query)
  console.log(req.body)
  res.status(404).send("Not implemented")
  // console.log(req.path)
})
// Implement the remaining routes similarly...

app.listen(4000, () => {
  console.log('Server is running on port 4000');
});