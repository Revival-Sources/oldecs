local thumb = game:GetService("ThumbnailGenerator")
local plr = game:GetService("Players"):CreateLocalPlayer(0)
local avatar = "JSON_AVATAR"
-- local bodycolors = JSON_COLORS
-- print(avatar)
plr:LoadCharacter()

local avatarParts = {}

-- Split the JSON_AVATAR string by semicolons and store each part in the avatarParts table, excluding the first part
local firstSemicolonIndex = avatar:find(";")
local contentprovider = game:GetService("ContentProvider")
if firstSemicolonIndex then
    local remainingString = avatar:sub(firstSemicolonIndex + 1)
    for part in remainingString:gmatch("([^;]+)") do
        -- Remove "www." from the part
        local cleanedPart = part:gsub("www%.", "")
        local cleanedPart2 = cleanedPart:gsub("http://oldecs.com/asset/?id=", "")
        local extractedPart = part:match(".*%?id=(.*)")
        table.insert(avatarParts, extractedPart)
    end
end
print("doing shit")
contentprovider:SetBaseUrl("https://www.oldecs.com")
-- Return the avatarParts table
for i,v in pairs(avatarParts) do
    -- print(v)
    -- print("https://www.oldecs.com/asset/?id="..v)
    local asset = game:GetObjects("https://www.oldecs.com/asset/?id="..v)[1]
    print(asset.Name)
    local hasgear = false
    for i,v2 in pairs(plr.Character:GetChildren()) do
    if v2:IsA("Tool") then
        hasgear = false
        break
    end
end
    -- table.insert()
    if not hasgear then
        if asset:IsA("Decal") or asset:IsA("Image") then
            local head2 = plr.Character.Head
            print(head2)
            if head2:FindFirstChild("face") ~= nil then
                head2.face:Destroy()
            end
            asset.Name = "face"
            asset.Parent = head2
        else
            asset.Parent = plr.Character
        end
    end
end
-- local bodyColorsData = game:GetService("HttpService"):JSONDecode(bodycolors)
-- local bodyColors = plr.Character:FindFirstChild("Body Colors")
local colors = {
    ['Head']      = "head22",
    ['Torso']     = "torso",
    ['Left Arm']  = "leftarm",
    ['Right Arm'] = "rightarm",
    ['Left Leg']  = "leftleg",
    ['Right Leg'] = "rightleg"
}

for part, color in pairs(colors) do
    if plr.Character:FindFirstChild(part) then
        print(color)
        plr.Character[part].BrickColor = BrickColor.new(color)
    else
        print("[warning] could not find",part,"in player")
    end
end
for _, object in pairs(plr.Character:GetChildren()) do
    if object:IsA('Tool') then
        print("Player has gear, raise the right arm out.")
        plr.Character.Torso['Right Shoulder'].CurrentAngle = math.rad(90)
    end
end

local thum = thumb:Click("PNG", 420, 420, true)

return thum