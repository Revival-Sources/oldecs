const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const cookieParser = require('cookie-parser')
const crypto = require('crypto');
const { Pool } = require('pg');
const argon2 = require('argon2');
app.use("/persistence/set", express.urlencoded({ extended: true }));
app.use("/persistence/getV2", express.urlencoded({ extended: true }));
app.use(express.json())
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
  
  app.post('/persistence/getV2', async(req, res) => {
    // console.log(req.headers)
    // console.log(req)
    // console.log(req.url)
    console.log(req.body)
    // console.log(req.path)
    // console.log(req)
    // console.log(req.query)
    // console.log(req.params)
    // res.status(200).send("Ok")
        console.log(req.url)
        const resp = await executeQuery(`SELECT * FROM datastores WHERE placeid = $1`, [req.query.placeId])
        console.log("where")
        // console.log(resp)
        // console.log(resp[0])

            // console.log(JSON.stringify(fullthing))
            // console.log(JSON.parse(JSON.stringify(fullthing)))
            if (resp[0]) {
                const data = resp.map(item => {
                    return {
                      "Value": item.value,
                      "Scope": item.scope,
                      "Key": item.key,
                      "Target": item.user_id
                    };
                  });
                  

                  
                    res.status(200).json({ "data": data });
                    console.log("real");
                    return;
            } if (!resp[0]) {
                  
                    res.status(200).json({ "data": [] });
                    console.log("real");
                    return;
                }

            // if
            // console.log(`{value: ${resp[0].value}}`)
    // console.log(req.headers)
    // res.redirect("/request-error?code=404");
  })
  app.post('/persistence/set', async (req, res) => {
    try {
      const key = req.query.key;
      const valueLength = req.query.valueLength;
      const value = req.body.value
      const target = req.query.target;
      console.log(req.body)
      const scope = req.query.scope;
      const placeId = req.query.placeId;
      console.log(`${key}, ${value}, ${valueLength}, ${target}, ${scope}, ${placeId}`)
        // console.log(`$`)
      const existingDatastore = await executeQuery('SELECT * FROM datastores WHERE key = $1 AND placeid = $2 AND user_id = $3 AND scope = $4 AND value = $5', [key, placeId, target, scope, value]);
      if (!existingDatastore[0]) {
        const insertQuery = 'INSERT INTO datastores ("key", "value", user_id, scope, placeid, valuelength) VALUES ($1, $2, $3, $4, $5, $6)';
        await executeQuery(insertQuery, [key, value, target, scope, placeId, valueLength]);
        res.status(200).json({ "data": [value] });
      } else {
        const updateQuery = 'UPDATE datastores SET "value" = $1 WHERE "key" = $2 AND placeid = $3 AND user_id = $4';
        await executeQuery(updateQuery, [value, key, placeId, target]);
        res.status(200).json({ "data": [value] });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'An error occurred while setting the datastore' });
    }
  });
  app.listen(4002, () => {
    console.log("Listening on 4002")
  })

  app.post("*", (req, res) => {
    console.log(req.url)
  })

  process.on('uncaughtException', () => {

  })