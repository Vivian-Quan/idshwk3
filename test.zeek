global IPuserTable: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
     local source_address: addr = c$id$orig_h;
     if(name=="USER-AGENT") {
          if(source_address in IPuserTable) {
               if(to_lower(value) !in IPuserTable[source_address]) {
                    add IPuserTable[source_address][to_lower(value)];
               }
          }
           else {
               IPuserTable[source_address] = set(to_lower(value));
          }
     }
}

event zeek_done()
{
     for(source_address in IPuserTable) {
          if(|IPuserTable[source_address]| >= 3) {
               print fmt("%s is a proxy", source_address);
          }
     }
}
