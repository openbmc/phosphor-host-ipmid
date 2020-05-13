                        Design-1:  IPMB design to handle requests from BIC                                                                                
                                                                                                          
                                                                             +-------+                    
                                      +--------+                             | ipmb  |                    
            +-----------------------+ |  d-bus |   +----------------------+  |       |  +--------------+  
            |                       | |        |   |                      |  +-------+  |              |  
            |                       | +--------+   |                      |             |  host-BIC1   |  
            |   host-ipmid          ----------------    ipmibridged       ---------------              |  
            |                       |              |                      |             |              |  
            |                       |              |                      |             |              |  
            |                       |              |                      |             +--------------+  
            +----------/------------+              +----------------------+                               
                       |                                                                                  
                       |                                                                                  
            +----------\------------+                                                                     
            |                       |                                                                     
            |  fb-ipmi-oem          |                                                                     
            |                       |                                                                     
            +-----------------------+                                                                     


    1. BIC will send ipmi request to host with a netfn = 0x38 and cmd = 1
    2. The commands from diffent host interfaces will be wrapped in to this request. 1. Intel ME, 2. SOL, 3. KCS
    3. The ipmi packet will be recived in ipmbbridge and the same will be sent to host-ipmid in the d-bus interfaces
    4. Host-ipmid will call the registered handler for oem_netfn = 0x38. The registered handler is ipmiOemBicHandler
    5. Implementation in the ipmiOemBicHandler
    5.1. Remover the wrapper and get the original ipmi command from the host interface
    5.2 Get the response for the command and wrap the response to netfn = 0x38 and cmd = 1
    6. This response will be sent back to ipmbridge from host-ipmid.
    7. ipmbbridge will sent back the response to BIC.
