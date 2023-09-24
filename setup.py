from flask import Flask, jsonify, send_file

app = Flask(__name__)

file_path = "version"  # Replace with your file path
file = open(file_path, "r")

# Read the entire contents of the file
file_contents = file.read()

# Close the file
file.close()

version = file_contents.replace("version-", "")
print(version)

@app.route('/version', methods=['GET'])
def get_version():
    print("Making request to version")
    return send_file("C:/project/version")
@app.route("/bootstrapper", methods=['GET'])
def bootstrapperdownload():
    return send_file("C:/project/Bootstrapper.exe", download_name="OldEcsPlayerLauncher.exe")
# @app.route('/versionQTStudio', methods=['GET'])
# def get_studioqt():
    # print("Making request to version")
    # return send_file("C:/project/versionqts")

@app.route('/version', methods=['POST'])
def post_version():
    print("Making request to version")
    return send_file("C:/project/version")

@app.route('/', methods=['GET'])
def access_denied():
    return jsonify(message="Access denied")


@app.route(f"/version-{version}-RobloxVersion.txt", methods=["GET"])
def robloxversion():
    return send_file("C:/project/RobloxVersion")

@app.route(f"/version-{version}-Oldecs.exe", methods=["GET"])
def robloxexe():
    print("test")
    return send_file("C:/project/Roblox.exe")


@app.route(f"/version-{version}-RobloxProxy.zip", methods=["GET"])
def robloxproxy():
    print("test")
    return send_file("C:/project/RobloxProxy.zip")
@app.route(f"/version-{version}-NPRobloxProxy.zip", methods=["GET"])
def nprobloxproxy():
    print("test")
    return send_file("C:/project/NPRobloxProxy.zip")

@app.route(f"/version-{version}-rbxManifest.txt", methods=["GET"])
def robloxmanifest():
    print("test")
    return send_file("C:/project/rbxManifest.txt")

@app.route(f"/version-{version}-template", methods=["GET"])
def template():
    print("test")
    return send_file("C:/project/template")

@app.route(f"/version-{version}-RobloxApp.zip", methods=["GET"])
def robloxapp():
    print("test")
    return send_file("C:/project/RobloxApp.zip")

@app.route(f"/version-{version}-content-terrain.zip", methods=["GET"])
def terrain():
    print("test")
    return send_file("C:/project/content-terrain.zip")

@app.route(f"/version-{version}-Libraries.zip", methods=["GET"])
def libraries():
    print("test")
    return send_file("C:/project/Libraries.zip")

@app.route(f"/version-{version}-content-textures3.zip", methods=["GET"])
def textures3():
    print("test")
    return send_file("C:/project/content-textures3.zip")
@app.route(f"/version-{version}-content-textures.zip", methods=["GET"])
def textures():
    print("test")
    return send_file("C:/project/content-textures.zip")
@app.route(f"/version-{version}-content-textures2.zip", methods=["GET"])
def textures2():
    print("test")
    return send_file("C:/project/content-textures2.zip")
@app.route(f"/version-{version}-redist.zip", methods=["GET"])
def redist():
    print("test")
    return send_file("C:/project/redist.zip")

@app.route(f"/version-{version}-content-sky.zip", methods=["GET"])
def sky():
    print("test")
    return send_file("C:/project/content-sky.zip")

@app.route(f"/version-{version}-content-music.zip", methods=["GET"])
def music():
    print("test")
    return send_file("C:/project/content-music.zip")

@app.route(f"/version-{version}-content-fonts.zip", methods=["GET"])
def fonts():
    print("test")
    return send_file("C:/project/content-fonts.zip")

@app.route(f"/version-{version}-shaders.zip", methods=["GET"])
def shaders():
    print("test")
    return send_file("C:/project/shaders.zip")

@app.route(f"/version-{version}-content-particles.zip", methods=["GET"])
def particles():
    print("test")
    return send_file("C:/project/content-particles.zip")

@app.route(f"/version-{version}-content-sounds.zip", methods=["GET"])
def sounds():
    print("test")
    return send_file("C:/project/content-sounds.zip")

if __name__ == '__main__':
    app.run(port=4001)