"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const axios_1 = require("axios");
const acl = axios_1.default.create({
    headers: {
        'user-agent': 'GameServer/1.0',
    }
});
function createsoaprequest(script, jobId) {
    return __awaiter(this, void 0, void 0, function* () {
        const xml = `<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <OpenJobEx xmlns="http://roblox.com/">
            <job>
                <id>${jobId}</id>
                <category>0</category>
                <cores>1</cores>
                <expirationInSeconds>43200</expirationInSeconds>
            </job>
            <script>
                <name>GameStart</name>
                <script>
                <![CDATA[
                ${script}
                ]]>
                </script>
            </script>
        </OpenJobEx>
      </soap:Body>
    </soap:Envelope>`;
        console.log(xml);
        return xml;
    });
}
(() => __awaiter(void 0, void 0, void 0, function* () {
    const request = yield createsoaprequest(`print("Hi")`, "job");
    // console.log(request)
    console.log(request);
}))();
//# sourceMappingURL=rendering.js.map