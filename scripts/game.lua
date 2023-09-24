
local asset = "ASSET_ID"


game:GetService("ContentProvider"):SetBaseUrl("https://www.oldecs.com")

game:Load("https://www.oldecs.com/asset/?id="..asset)

local thum = game:GetService("ThumbnailGenerator"):Click("PNG", 820, 820, false)
return thum