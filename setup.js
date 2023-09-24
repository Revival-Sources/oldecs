const express = require('express');
const { join } = require('path');

const app = express();

const file_path = "version";  // Replace with your file path
const file_path2 = "versionqts";
const fs = require('fs');

// Read the entire contents of the file
const file_contents = fs.readFileSync(file_path, 'utf8');
const file_contents2 = fs.readFileSync(file_path2, 'utf8');

const version = file_contents.replace("version-", "");
const qtstudiover = file_contents2.replace("version-", "");
console.log(version);

app.get('/version', (req, res) => {
  console.log("Making request to version");
  res.sendFile(join(__dirname, "version"));
});

app.get('/bootstrapper', (req, res) => {
  res.download(join(__dirname, "Bootstrapper.exe"), "OldEcsPlayerLauncher.exe");
});

app.get('/versionQTStudio', (req, res) => {
  console.log("Making request to version QT Studio");
  res.sendFile(join(__dirname, "versionqts"));
});

app.post('/version', (req, res) => {
  console.log("Making request to version");
  res.sendFile(join(__dirname, "version"));
});

app.get('/', (req, res) => {
  res.json({ message: "Access denied" });
});

app.get(`/version-${version}-RobloxVersion.txt`, (req, res) => {
  res.sendFile(join(__dirname, "RobloxVersion"));
});

app.get(`/version-${version}-Oldecs.exe`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "Roblox.exe"));
});

app.get(`/version-${version}-RobloxProxy.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "RobloxProxy.zip"));
});

app.get(`/version-${version}-NPRobloxProxy.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "NPRobloxProxy.zip"));
});

app.get(`/version-${version}-rbxManifest.txt`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "rbxManifest.txt"));
});

app.get(`/version-${version}-template`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "template"));
});

app.get(`/version-${version}-RobloxApp.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "RobloxApp.zip"));
});

app.get(`/version-${version}-content-terrain.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-terrain.zip"));
});

app.get(`/version-${version}-Libraries.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "Libraries.zip"));
});

app.get(`/version-${version}-content-textures3.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-textures3.zip"));
});

app.get(`/version-${version}-content-textures.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-textures.zip"));
});

app.get(`/version-${version}-content-textures2.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-textures2.zip"));
});

app.get(`/version-${version}-redist.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "redist.zip"));
});

app.get(`/version-${version}-content-sky.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-sky.zip"));
});

app.get(`/version-${version}-content-music.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-music.zip"));
});

app.get(`/version-${version}-content-fonts.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-fonts.zip"));
});

app.get(`/version-${version}-shaders.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "shaders.zip"));
});

app.get(`/version-${version}-content-particles.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-particles.zip"));
});

app.get(`/version-${version}-content-sounds.zip`, (req, res) => {
  console.log("test");
  res.sendFile(join(__dirname, "content-sounds.zip"));
});
app.get(`/version-${qtstudiover}-BootstrapperQTStudioVersion.txt`, (req, res) => {
    res.sendFile(join(__dirname, "versionqts"));
})
app.get(`/cdn.txt`, (req, res) => {
    res.status(200).send("setup.oldecs.com")
})
app.get("*", (req, res) => {
    console.log(`request to: ${req.url}`)
})
app.get(`/version-${qtstudiover}-OldEcsStudioLauncherBeta.exe`, (req, res) => {
    console.log("test");
    res.sendFile(join(__dirname, "OldEcsStudioLauncherBeta.exe"));
  });
const port = 4001;
app.listen(port, () => {
  console.log(`Express app listening on port ${port}`);
});