local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
This script tests for Cross-Site Scripting (XSS) vulnerabilities by injecting a payload into query parameters and checking if the payload is reflected in the response.
]]

categories = {"vuln", "exploit"}
author = "YourName"
license = "Same as Nmap-- See scanme.nmap.org
portrule = shortport.port_or_service(80, "http")

action = function(host, port)
	local xss_payload = "<script>alert('XSS')</script>"
	local target_path = "/?input=" .. stdnse.url_escap(xss_payload)
	local response = http.get(host, port, target_path)

	if response and response.body then
		if response.body:find(xss_payload, 1, true) then
			return "Potential XSS vulnerability detected! Payload reflected in response."
		else
			return "No XSS vulnerability detected. Payload not reflected in response."
		end
	else
		return "Failed to retrieve response from the server."
	end
end
