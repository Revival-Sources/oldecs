local asset = "ASSET_ID"
local assetType = 2


game:GetService("ContentProvider"):SetBaseUrl("https://www.oldecs.com")
local assetUrl
if assetType == 18 then
local ok, image = pcall(function() 
    return game:GetObjects("https://www.oldecs.com/asset/?id="..asset)[1]
end)
print("LoadAsset() pcall over - result",ok,image)
if ok then
    if image.ClassName == "Decal" then
        assetUrl = image.Texture
    else
        for _, item in pairs(image:GetChildren()) do
            if item.ClassName == "Decal" then
                assetUrl = item.Texture
                break
            end
        end
    end
end
end
local ok, image = pcall(function() 
    return game:GetObjects("https://www.oldecs.com/asset/?id="..asset)[1]
end)
if ok then
    print(image)
assetUrl = "https://www.oldecs.com/asset/?id="..image.Graphic:match("%d+")
end
local thum = game:GetService("ThumbnailGenerator"):ClickTexture(assetUrl, 'png', 420, 420)
print(thum)

return thum