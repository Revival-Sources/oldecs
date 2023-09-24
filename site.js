const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser')
const crypto = require('crypto');
const { Pool } = require('pg');
const argon2 = require('argon2');

const dbConfig = {
    host: '127.0.0.1',
    database: 'bloxie',
    user: 'postgres',
    password: 'bloxie@',
  };

  const pool = new Pool(dbConfig);

async function executeQuery(query, values) {
  const client = await pool.connect();
  try {
    const result = await client.query(query, values);
    return result.rows;
  } finally {
    client.release();
  }
}


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
                                 "PlaceId":${gameid},
                                   "CreatorId":2,
                                 "GameId":"${jobid}",
                                   "MachineAddress":"http://127.0.0.1",
                                   "GsmInterval":5,
                                     "MaxPlayers":30,
                               "MaxGameInstances":51,
                                "ApiKey":"",
                               "PreferredPlayerCapacity":30,
                                 "DataCenterId":"69420",
                                 "PlaceVisitAccessKey":"",
                                 "UniverseId":${gameid},
                                 "PlaceFetchUrl":"http://www.oldecs.com/asset/?id=${gameid}",
                                 "MatchmakingContextId":1,
                                 "CreatorId":1,
                                 "CreatorType":"User",
                                 "PlaceVersion":1,
                                 "BaseUrl":"www.oldecs.com",
                                 "JobId":"${jobid}",
                                 "script":"print('Initializing NetworkServer.')",
                                 "PreferredPort":${port}
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
    const base64 = await axiosClient.post("http://127.0.0.1:64989", xml).then((data) => {

      })
      return base64;
    }
    }

app.use(cookieParser());



function generateCookieString(length) {
    const crypto = require('crypto');
    const bytes = crypto.randomBytes(length);
    const stringBuilder = [];
  
    for (let i = 0; i < bytes.length; i++) {
      stringBuilder.push(bytes[i].toString(16).padStart(2, '0'));
    }
  
    return stringBuilder.join('');
  }

  const axios = require('axios');
// const path = require('path');

const async = require('async');
const axiosClient = axios.default.create({
  headers: {
      'user-agent': 'OldEcs/1.0',
  }
});

  const sign = true
app.all('/Game/Join.ashx', async (req, res) => {
  // if (!req.query.cookie) {
    // res.status(400).send('Cookie is missing');
    // return;
  // }
  // res.redirect("https://www.roblox.cat//game//join.ashx?serverPort=30764&gameid=2629&jobid=d4b9b073-a813-404a-1759-17ea4f8a5ad4&rbxsig=2&type&type=2018")

  const cookieQuery = req.query.cookie;
  const formatString = '--rbxsig2%{0}%{1}';

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
      console.log(`Making request to ${placeid} game/join.ashx`)
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

      try {
        
        const usernameMatch = ticket.match(/username=([^;]+)/);
        const username = usernameMatch ? usernameMatch[1] : "";
    
        const useridMatch = ticket.match(/userid=([^;]+)/);
        const userid = useridMatch ? useridMatch[1] : "";
    
        const membershipMatch = ticket.match(/membership=([^;]+)/);
        const membership = membershipMatch ? membershipMatch[1] : "";
        let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
        modifiedScript = script.replace('USERNAMEHERE', username ?username : `Guest ${randomNumber}`);
        modifiedScript = modifiedScript.replace('USERIDHERE2', userid ? userid : -1);
      modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
      modifiedScript = modifiedScript.replace('USERIDHERE', userid ? userid : -1);
      modifiedScript = modifiedScript.replace('useridherer', userid ? userid : -1);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', membership || 'None');
      // modifiedScript = modifiedScript.replace("53640", portid)
      modifiedScript = modifiedScript.replace("1939", placeid).replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid)
      modifiedScript = modifiedScript.replace("RANDOMGUIDHERE", uuidv4())
      // const scriptBytes = Buffer.from(modifiedScript, 'utf-8');
      // if (sign) {
        // modifiedScript = modifiedScript.replace("--rbxsig%JwjE0x5uYjBTzlQxiL9yOxr+kgfMttA/VfGdVVRI9zJ+emY8XITOcLmqxryZiRmq5HA5NA3HBmTOq8HspTZdDtm2LdqFHY8aY9cjyEsxWKw/hCGRersXdiCZDxxaVKC9Co6YBwh0LVcKy60mJSRrUOyuiSG4fK8NSRf8qQEfuqs=%", "")
      // }
    

      const { privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
    

      const signer = crypto.createSign('sha1');
      const signature = axiosClient.post(`http://localhost:4003/sign?script=${privateKey}`)
      signer.update(scriptBytes);
      const signature2 = signer.sign(privateKey);
      axiosClient
    


      const signatureBase64 = signature.toString('base64');

      const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);
    
      res.set('Content-Type', 'application/json');
     return res.send(sign ? formattedScript : modifiedScript);
      // return
      } catch (e) {
        let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
        modifiedScript = script.replace('USERNAMEHERE', `Guest ${randomNumber}`);
        modifiedScript = modifiedScript.replace('USERIDHERE2', -1);
      modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
      modifiedScript = modifiedScript.replace('USERIDHERE', -1);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', 'None');
      modifiedScript = modifiedScript.replace("53640", portid)
      modifiedScript = modifiedScript.replace("1939", placeid).replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid)
      const scriptBytes = Buffer.from(modifiedScript, 'utf-8');
    

      const { privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
    

      const signer = crypto.createSign('sha1');
      signer.update(scriptBytes);
      const signature = signer.sign(privateKey);
    

      const signatureBase64 = signature.toString('base64');
    

      const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);
    
      res.set('Content-Type', 'application/json');
      return res.send(sign ? formattedScript : modifiedScript);
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


    let modifiedScript = script
    if (cookieQuery) {
      modifiedScript = script.replace('USERNAMEHERE', username);
      modifiedScript = modifiedScript.replace('USERIDHERE2', `${userId.toString()}`);
    modifiedScript = modifiedScript.replace("DATEHERE", formattedDate)
    modifiedScript = modifiedScript.replace('USERIDHERE', userId.toString());
    modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', user.membership || 'None').replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid);
    } else if (!cookieQuery) {
      let randomNumber = Math.floor(Math.random() * (9999 - 100) + 100);
      modifiedScript = script.replace('USERNAMEHERE', `Guest ${randomNumber}`);
      modifiedScript = modifiedScript.replace('USERIDHERE', `-1`);
      modifiedScript = modifiedScript.replace('USERIDHERE2', `-1`);
      modifiedScript = modifiedScript.replace('MEMBERSHIPTYPEHERE', 'None');
      const stringtoreplace = `DATEHERE;ewtG0BFnAtFJEQAdSi2CXBVCwE2QuuTyWcWSq1D1iehqtmuQL7q/kBdLntpGrlyGRlTkZwsQTcG8azv2oKSf2zHmQvdq9iEgRy9mXqAkbDJMftq4sqFjif8Y20dCYYTCatG7Dse7P+FTLZNQqR/Xp9mhh6nzVVrFjlLL5UAXsxCFnYU6YsJbtQhM21i+lbb67dNmsin3TKTqWZNQhTaZuxagQXICfCILk+9csD7W/+f7R1l6simuxGIjaT4JshX3BjqrL6U7O4yy37ZAxTEkIvUuZmkHr2WRr4TtWUYSjGTE0ylV+6h31IE/iwEQe91mDP600hyNc7BjkRTXWG5Avg==;pCi0ISsnpOSOfhnLlsdDFodtlx07v7kZHctrIOWFSF9hNCO3RSSg5Epnrmyym0GbuLlpvNjFGTjoWTt4Ax96Ylp1RsYpHRg6G+WBJfwv9L88Os+lPzMYgf5LuoAgsIlcvzR0tYmkUVc4+A2zaQpNVGavHwfPPdkmcxsEHMEke5rnFQzye8nqKwOJpG+8lIbRYEgfRm8bzgLBW7pdD+ufNWq9162YUO6AfoEZTXoHoefOczYW6C4FyIUBjL3kn/VaJwSuceICuF5Q4jxZyP3Qt+blztqSLu0QboSkym01CcY6U4dwtOE3eV9S9uPDt4QBh+PdtTvHqcSN/K5udDx/vA==;2`
      modifiedScript = modifiedScript.replace(stringtoreplace, ``).replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid).replace("PLACEIDHERE", req.query.placeid)
    }
    modifiedScript = modifiedScript.replace("RANDOMGUIDHERE", uuidv4())


    const scriptBytes = Buffer.from(modifiedScript, 'utf-8');


    const { privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });


    const signer = crypto.createSign('sha1');
    signer.update(scriptBytes);
    const signature = signer.sign(privateKey);


    const signatureBase64 = signature.toString('base64');


    const formattedScript = formatString.replace('{0}', signatureBase64).replace('{1}', modifiedScript);

    res.set('Content-Type', 'application/json');
    res.send(formattedScript);
  } catch (error) {
    console.error('Error: ', error);
    res.status(500).send('Internal Server Error');
  }
});
app.get("/joinscript", async (req, res) => {
  const cookie = req.cookies?.OLDECS_SECURITY
  const ticket = cookie
  const isguest = req.query.guest
  const id = req.query.placeid
  const port = req.query.port
  if (!port || !id) {
    // res.status(400).send("Please follow the instructions.")
    // return;
  }
  res.set('Content-Type', 'application/json');
  if (ticket && !isguest || ticket && isguest == 0) {
    res.send(`-a https://www.oldecs.com/Login/Negotiate.ashx -j "https://www.oldecs.com/Game/Placelauncher.ashx?cookie=${ticket}&placeid=${id}" -t ${ticket}`)
  } else if (!ticket) {
    res.send(`-a "https://www.oldecs.com/Login/Negotiate.ashx" -j "https://www.oldecs.com/Game/Placelauncher.ashx?placeid=${id}" -t ""`)
  } else if (isguest == 1) {
    res.send(`-a "https://www.oldecs.com/Login/Negotiate.ashx" -j "https://www.oldecs.com/Game/Placelauncher.ashx?placeid=${id}" -t ""`)
  }
})
app.all("/favicon.ico", (req,res)=>{
  try {
    res.status(200).sendFile(path.join(__dirname, "Roblox.ico"))
  } catch (e) {
    res.status(400).type("application/json").send("error")
  }
})

app.all('/Game/PlaceLauncher.ashx', async(req, res) => {
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
    let modifiedContent = fileContent.replace("?cookie=cookie", `?t=${ticket}`).replace('cookie=cookie', ``).replace("placeidhereblud", req.query.placeid);
    const resu = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid])
    console.log(resu)
    let jobid
    // console.log(resu[0])
    let game
    if (resu[0] && resu[0].running == false) { 
      console.log("Starting server lul")
      await creategameserver(req.query.placeid, resu[0].asset_id, res)
    }
    let runninggames = await executeQuery(`SELECT * FROM running_games WHERE id = $1`, [req.query.placeid]);
    if (runninggames) {
      console.log(runninggames)
      game = await executeQuery(`SELECT * FROM games WHERE id = $1`, [req.query.placeid]);
      console.log(game[0])
      jobid = game[0].job_id
    }
    modifiedContent = modifiedContent.replace("testing123", jobid)
    
    const decoded = await decodeticket(req.query.t)
    // const decoded =console.log("POST") unescapeUnicode(decoded2)
    res.set('Content-Type', 'application/json');
    res.send(`{"jobId":"${jobid}","status":${game[0].status},"joinScriptUrl":"https://www.oldecs.com/Game/Join.ashx?placeid=${req.query.placeid}", "authenticationUrl":"https://www.oldecs.com/Login/Negotiate.ashx","authenticationTicket":"Test","message":"null"}`);
  }
  });
  function generaterandomnumber(start, end) {
    let randomNumber = Math.floor(Math.random() * (end - start) + start);
    return randomNumber
  }
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
    const status = 0
    await executeQuery(`UPDATE games SET status = $1 WHERE id = $2`, [status, gameid])
    const jobId = generateCookieString(10)
    await rccjson("GameServer", "GameServer", [games[0].asset_id,gameid,port,"https://www.oldecs.com"],port,games[0].asset_id,jobId,gameid).then((async (data) => {
      if (data == null) {
        res.type("application/json")
        const status = 4
        await executeQuery(`UPDATE games SET status = $1 WHERE id = $2`, [status, gameid])
        res.status(200).json({"jobId": jobId, "status": status,"joinScriptUrl": `https://www.oldecs.com/Game/Join.ashx?placeid=${gameid}`, "authenticationUrl": "https://www.oldecs.com/Login/Negotiate.ashx","authenticationTicket": "","message":null});
      } else {
        console.log(data)
        const status = 2
        await executeQuery('INSERT INTO running_games (id) VALUES ($1)', [gameid]);
        await executeQuery(`UPDATE games SET running = true WHERE id = $1`, [gameid])
        await executeQuery(`UPDATE games SET port = $1 WHERE id = $2`, [thing,gameid])
        await executeQuery(`UPDATE games SET job_id = $1 WHERE id = $2`, [jobId, gameid])
        await executeQuery(`UPDATE games SET status = $1 WHERE id = $2`, [status, gameid])
      }
    }))
    return
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
  app.get("/marketplace/productinfo",(req,res)=>{
    console.log("Getting product info")
    res.status(200).json({"AssetId":1,"ProductId":1,"Name":"Life's Place","Description":"Welcome To OldEcs!","AssetTypeId":19,"Creator":{"Id":2,"Name":"Life","CreatorType":"User","CreatorTargetId":1},"IconImageAssetId":0,"Created":"2023-07-23T08:29:09.510Z","Updated":"2023-07-23T08:29:09.510Z","PriceInRobux":null,"PriceInTickets":null,"Sales":0,"IsNew":false,"IsForSale":true,"IsPublicDomain":false,"IsLimited":false,"IsLimitedUnique":false,"Remaining":null,"MinimumMembershipLevel":0,"ContentRatingTypeId":0})
  })
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

    // axiosClient.get(`https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`).then((data) => {
      // fs.writeFileSync(`Assets/${assetId}`, Buffer.from(data.data))
      // res.sendFile(`C:/project/Assets/${assetId}`)
    // })
    // res.redirect(`https://assetdelivery.roblox.com/v1/asset/?id=${assetId}`)
    // downloadQueue.push({ assetId, assetPath, res, retryAttempts: 0 });
  });
  app.get('//asset', (req, res) => {
    const assetId = req.query.id || req.query.ID;
    // console.log(`Asset id: ${assetId}`);
    res.redirect(`/asset/?id=${assetId}`)
    // downloadQueue.push({ assetId, assetPath, res, retryAttempts: 0 });
  });
async function decodeticket(ticket) {
  let tick = ticket.replace(" ", "")
  // console.log(tick)
  let buff = new Buffer.from(tick, 'base64');
  let decodedString = buff.toString('utf-8');
  console.log(decodedString)
  // const decodedString = decodedBuffer.toString('ascii');
  return decodedString;
}

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
    const data = `;username=${users[0].username};userid=${users[0].id};membership=${users[0].membership}`;
    // const buff = Buffer.from(data, 'ascii');
    // const base64data = buff.toString('base64');
    stringBuilder.push(data);
  }

  const ticket = Buffer.from(stringBuilder.join(''), 'ascii').toString('base64');

  return ticket;
}
  app.post("/Login/NewAuthTicket", async(req, res) => {
    const cookiestring = (await generateTicket(20, req.cookies?.OLDECS_SECURITY))
    if (gueston || req.cookies?.OLDECS_SECURITY) {
      res.send(cookiestring)
    } else {
      res.send("Not logged in.")
    }
  })


  app.get('/Login/Negotiate.ashx', (req, res) => {

    const filePath = path.join(__dirname, 'Pages', 'negotiate.ashx');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  app.post('/Login/Negotiate.ashx', (req, res) => {

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

    const filePath = path.join(__dirname, 'Pages', 'fflags.cshtml');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });
  
  app.get('/Setting/QuietGet/ClientSharedSettings', (req, res) => {

    const filePath = path.join(__dirname, 'Pages', 'fflags.cshtml');
    const fileContent = fs.readFileSync(filePath, 'utf-8');
    res.setHeader('Content-Type', 'application/json');
    res.send(fileContent);
  });

  app.all("/v1.1/avatar-fetch", async(req, res) => {
    res.type("application/json")
    res.status(200).send(`{"resolvedAvatarType":"R15","accessoryVersionIds":[4],"equippedGearVersionIds":[],"backpackGearVersionIds":[],"bodyColors":{"HeadColor":1001,"LeftArmColor":1001,"LeftLegColor":1001,"RightArmColor":1001,"RightLegColor":1001,"TorsoColor":1001},"animations":{"Run":969731563},"scales":{"Width":1.0000,"Height":1.0500,"Head":1.0000,"Depth":1.00,"Proportion":0.0000,"BodyType":0.0000}}`)
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
    console.log("GET")
    console.log(req.url)
    console.log(req.query)
    // console.log(req.path)
    console.log(req.body)
    console.log("GET")
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
    console.log("POST")
    res.status(404).send("Not implemented")
    // console.log(req.path)
  })
  process.on("uncaughtException", (e) => {
    console.log(e)
  })
  app.listen(4000, () => {
    console.log('Server is running on port 4000');
  });