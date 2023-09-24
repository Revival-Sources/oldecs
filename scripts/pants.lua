local asset = "ASSET_ID"

game:GetService("ContentProvider"):SetBaseUrl("https://www.oldecs.com")

local asset = game:GetObjects("https://www.oldecs.com/asset/?id="..asset)[1]

local plr = game:GetService("Players"):CreateLocalPlayer(0)

plr:LoadCharacter()

asset.Parent = plr.Character

local thum = game:GetService("ThumbnailGenerator"):Click("PNG", 820, 820, true)
return thum