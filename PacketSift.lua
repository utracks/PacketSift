
-- Protocol-aware packet sniffer with advanced filtering

local plugin_info = {
    version = "1.0",
    author = "utracks",
    description = "Custom Packet Sniffer with Filtering"
}

-- Configuration
local config = {
    filters = {
        {
            name = "Suspicious HTTP",
            filter = "http and (http.request.uri contains \"cmd=\" or http.request.uri contains \"exec=\")",
            severity = 80
        },
        {
            name = "DNS Tunneling",
            filter = "dns and (dns.qry.name.len > 50 or dns.qry.type in {10,16})",
            severity = 85
        },
        {
            name = "Unencrypted Credentials",
            filter = "tcp and (tcp.payload matches \"(user|pass|pwd)=[^&]+\")",
            severity = 90
        }
    },
    capture_interface = "eth0",
    sample_size = 100, -- packets per filter
    alert_enabled = true
}

-- Packet capture using Wireshark's tap system
local sniffer = Proto("customsniff", "Custom Sniffer")

-- Field extractors
local f_src = Field.new("ip.src")
local f_dst = Field.new("ip.dst")
local f_proto = Field.new("frame.protocols")

local function packet_listener()
    local tap = Listener.new(nil, "frame")
    
    function tap.packet(pinfo, tvb)
        for _, filter in ipairs(config.filters) do
            if pinfo.visited or not apply_filter(pinfo, filter.filter) then
                goto continue
            end
            
            -- Capture sample
            if not samples[filter.name] then
                samples[filter.name] = 0
            end
            if samples[filter.name] < config.sample_size then
                samples[filter.name] = samples[filter.name] + 1
                
                -- Create alert
                local alert = string.format(
                    "%s: %s -> %s (%s)",
                    filter.name,
                    tostring(f_src()),
                    tostring(f_dst()),
                    tostring(f_proto())
                )
                
                if config.alert_enabled then
                    register_alert(filter.name, alert, filter.severity)
                end
                
                -- Add to packet list
                table.insert(captured_packets, {
                    filter = filter.name,
                    packet = pinfo.number,
                    summary = alert
                })
            end
            
            ::continue::
        end
    end
    
    function tap.draw()
        -- Display summary
        print("\nCapture Summary:")
        for filter, count in pairs(samples) do
            print(string.format("%s: %d packets", filter, count))
        end
    end
end

-- Initialize
local samples = {}
local captured_packets = {}

function sniffer.init()
    local timer = Timer.new("sniffer_start", 1, packet_listener)
    timer:start()
end

register_postdissector(sniffer)