local asset = "ASSET_ID"


game:GetService("ContentProvider"):SetBaseUrl("https://www.oldecs.com")


game:GetObjects("https://www.oldecs.com/asset/?id="..asset)[1].Parent = workspace

local thum = game:GetService("ThumbnailGenerator"):Click("PNG", 820, 820, true, true)

return thum