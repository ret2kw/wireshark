do

    print("Analyze Domain Login Times")

    local mac_address = ""
    local gpo_log = ""

    local smb_sess = {}
    --we need to track file guids to map them back to human names so we know what is closing
    local file_ids = {}

    --lets build our filter for the mac address of our target machine
    local new_filter = "eth.src == " .. mac_address .. " || eth.dst == " .. mac_address 

    --print(new_filter)


    --login traffic consists of DNS, Kerberos, DCERPC, CLDAP, LDAP, SMB2

    --we need to capture the time of each packet
    local a_time = Field.new("frame.time_epoch")

    --we want to see when the machine gets an ip address
    local dhcp_type = Field.new("bootp.type")
    local dhcp_adress = Field.new("bootp.ip.your")

    --we want to know dns traffic
    local dns_query = Field.new("dns.qry.name")

    --we want CLDAP traffic
    local cldap = Field.new("cldap")

    --we want LDAP traffic
    local ldap = Field.new("ldap")

    --we want RPC NETLOGON traffic
    local rpc_netlogon = Field.new("rpc_netlogon")
    --this is so we know when successful auth
    local rpc_authcode = Field.new("netlogon.rc")

    --we want Kerberos auth requests
    local kb_as_req = Field.new("kerberos.msg.type")
    --we want the computer name for sanity check
    local kb_name = Field.new("kerberos.name_string")

    --we want SMB/2 traffic
    local smb = Field.new("smb")
    local smb2 = Field.new("smb2")
    --we want smb types
    local smb_cmd = Field.new("smb.cmd")
    local smb2_cmd = Field.new("smb2.cmd")
    --we want the session id
    local smb2_sess = Field.new("smb2.sesid")
    --we want the cmd sequence
    local smb2_cmdid = Field.new("smb2.seq_num")
    --we need the file guid so we can track file closes
    local smb2_fid = Field.new("smb2.fid")
    --we want the return code for the request
    local smb2_ntstatus = Field.new("smb2.nt_status")
    --we want the tree (dir) machine is connecting too
    local smb2_tree = Field.new("smb2.tree")
    --we want the filename to diff against gpos
    local smb2_filename = Field.new("smb2.filename")


    local function get_file(a_string)
        --helper func to get filename
        a_string = tostring(a_string)
        --nasty regex to pull out the filename
        local file = a_string:match".*%\\(.*%.*)"

        if file ~= nil then
            return file
        end
    end


    local function get_guid(a_string)
        --returns the guid from a file path
        a_string = tostring(a_string)

        if get_file(a_string) == "files" then
            return "files"
        end

        local start = a_string:find("{")
        local the_end = a_string:find("}")
  
        if start ~= nil and the_end ~= nil then
            local guid = a_string:sub(start + 1, the_end - 1)
            return guid:lower()
        end
    end
   
    local function get_gpos()
        --parse out the gpo guid to readable user name
        local gpo_list = {}
        gpo_list["files"] = "files"
        f = io.open(gpo_log, "r")
        
        for line in f:lines() do
            local guid = line:sub(0, line:find(":") - 1)
            local name = line:match".*%:(.*)" 
            gpo_list[guid:match( "^%s*(.-)%s*$" )] = name:match( "^%s*(.-)%s*$" )
        end

        return gpo_list 
    end    
            
 
    
    --the listener function, will create our tap
    local function init_listener()
        print("[*] Starting to Process Packets")
    
    
        --need frames and only look for the packets we are interested
        local tap = Listener.new("frame", new_filter)
    
        --tables to store when and what GPO related things are accessed
        --local open_req = {}
        --local close_req = {}
     
        --called for every packet meeting the filter set for the Listener()
        function tap.packet(pinfo, tvb)
        
            local filename = smb2_filename()      
        
            local cmd = smb2_cmd()
            local status = smb2_ntstatus()
            local sessid = smb2_sess()
            local cmd_id = smb2_cmdid()
            local f_guid = smb2_fid()

            local p_time = a_time()

            --print(cmd,filename)
            
            --lets look for create requests 0x0005 sent my machine
            if tostring(cmd) == "5" and filename ~= nil and status == nil then
            
                local tmpsess = tostring(sessid)
 
                --check if the session exists, if not lets add it
                if smb_sess[tmpsess] == nil then
                    smb_sess[tmpsess] = {}
                    smb_sess[tmpsess]['open_req'] = {}
                    smb_sess[tmpsess]['close_req'] = {}
                    smb_sess[tmpsess]['cmd_id'] = {}
                    smb_sess[tmpsess]['gpo_times'] = {}
                end 

                --add this cmd seq number to the session table
                if cmd_id ~= nil then
                    smb_sess[tmpsess]['cmd_id'][tostring(cmd_id)] = tostring(filename)
                end


                smb_sess[tmpsess]['open_req'][tostring(filename)] = tostring(p_time)
                --open_req[tostring(filename)] = tostring(p_time)                


            --lets get the create responses 0x0005 with a status of 0x00000000
            elseif tostring(cmd) == "5" and tostring(status) == "0" and f_guid ~= nil then
                --this is a success response, need to map guid to filename for close requests

                local tmpsess = tostring(sessid)

                local tmpseq = smb_sess[tmpsess]
                --print(tmpseq)

                if tmpseq['cmd_id'][tostring(cmd_id)] ~= nil then --we have recorded the request
                    local f_name = tmpseq['cmd_id'][tostring(cmd_id)]
                    file_ids[tostring(f_guid)] = f_name
                end         


            --lets look for close requests 0x0006
            elseif tostring(cmd) == "6" and status == nil then
                --mapping the file id to real name
               
                local tmpsess = tostring(sessid)
 
                --close_req[file_ids[tostring(f_guid)]] = tostring(p_time)
                smb_sess[tmpsess]['close_req'][file_ids[tostring(f_guid)]] = tostring(p_time)            


            --end of the cmd if block
            end
        
            

        --end of the tap.packet() func
        end

        --this function is called at the end of processing
        function tap.draw()
            --
            for s,t in pairs(smb_sess) do
                --print('-----SMBSESSION ' .. s .. '--------') 
                for k,v in pairs(smb_sess[s]['open_req']) do

                    if smb_sess[s]['close_req'][k] ~= nil then                    
                        --print('[*] Took ' .. smb_sess[s]['close_req'][k] - v .. ' to open ' .. k)

                        local close_time = smb_sess[s]['close_req'][k]

                        if smb_sess[s]['gpo_times'][get_guid(k)] == nil then
                            smb_sess[s]['gpo_times'][get_guid(k)] = {}
                        end

                        if smb_sess[s]['gpo_times'][get_guid(k)]['first'] ~= nil then
                            if v < smb_sess[s]['gpo_times'][get_guid(k)]['first'] then
                                smb_sess[s]['gpo_times'][get_guid(k)]['first'] = v
                            end
                        end

                        if smb_sess[s]['gpo_times'][get_guid(k)]['last'] ~= nil then
                            if smb_sess[s]['close_req'][k] > smb_sess[s]['gpo_times'][get_guid(k)]['last'] then
                                smb_sess[s]['gpo_times'][get_guid(k)]['last'] = smb_sess[s]['close_req'][k]
                            end
                        end

                        if smb_sess[s]['gpo_times'][get_guid(k)]['first'] == nil then
                            --print('the else loop')
                            smb_sess[s]['gpo_times'][get_guid(k)]['first'] = v
                            smb_sess[s]['gpo_times'][get_guid(k)]['last'] = smb_sess[s]['close_req'][k]                       
                        end
                    end
                end
            end

            local gpo_names = get_gpos()

            for s,ts in pairs(smb_sess) do
                print('-----SMBSESSION ' .. string.format("0x%x", s) .. '--------')
                for g,t in pairs(smb_sess[s]['gpo_times']) do
                    print("[*] GPO " .. gpo_names[g] .. " took: " .. tonumber(smb_sess[s]['gpo_times'][g]['last']) - tonumber(smb_sess[s]['gpo_times'][g]['first']) .. " seconds")
                end
            end  

        --tap.draw() end
        end

    --init_listener() end
    end 
    

    init_listener()

end

