# encoding = utf-8

def process_event(helper, *args, **kwargs):
    import json
    
    helper.log_info("Alert action searching_domains started.")
    
    proxy = helper.get_proxy()
    
    if proxy:
        use_proxy = True
    else:
        use_proxy = False
    
    #Get Global Parameters
    api_key = helper.get_global_setting("api_key")
    index_name = helper.get_global_setting("index")
    
    #Get Local Parameters
    keyword_search = helper.get_param("keyword_search")
    value = helper.get_param("value")
    value_search = helper.get_param("value_search")
    search_description = helper.get_param("search_description")
    
    #Create the URI String that looks for the domain
    url = 'https://api.securitytrails.com/v1/search/list'
    
    #Specify Method
    method = "POST"
    
    #Create filter
    values = {}
    values['filter'] = {}
    values['filter'][value] = value_search 
    values['filter']['keyword'] = keyword_search
    
    values_payload = json.dumps(values)
    
    #Create Header Values
    headers = {
    'Content-Type': 'application/json',
    'APIKEY' : '{}'.format(api_key)
    }
    
    #Make HTTP Request
    response = helper.send_http_request(url, method, parameters=None, payload=values_payload, headers=headers, cookies=None, verify=True, cert=None, timeout=10, use_proxy=use_proxy)

    if response.status_code == 200:
        #Log successfull request
        helper.log_info("Received 200 OK from security trails for value {}:{} with keyword of {}.".format(value,value_search,keyword_search))
        
        #Add note information to JSON output
        json_load = response.json()
        json_load['search_description'] = search_description
        json_load['search_type'] = "Exploration Domain Search"
        
        #Convert output to JSON String
        json_data = json.dumps(json_load)
        
        #Add Event to Adaptive Response Framework
        helper.addevent(json_data, sourcetype="securitytrails:json")
        try:
            #Try writing to the specified index in global settings
            helper.writeevents(source="securitytrails", index=index_name, host="adaptive_response")
        except Exception as e:
            #If that fails write this as an exception
            helper.log_error("Error with writing event. Error Message:{}".format(e))

    elif response.status_code == 400:
        #Log successfull request
        helper.log_info("Received 400 error from security trails for value {}:{} with keyword of {}.".format(value,value_search,keyword_search))
        
        #Add note information to JSON output
        json_load = response.json()
        json_load['search_description'] = search_description
        json_load['domain'] = domain
        json_load['search_type'] = "Exploration Domain Search"
        
        #Convert output to JSON String
        json_data = json.dumps(json_load)
        
        #Add Event to Adaptive Response Framework
        helper.addevent(json_data, sourcetype="securitytrails:json")
        try:
            #Try writing to the specified index in global settings
            helper.writeevents(source="securitytrails", index=index_name, host="adaptive_response")
        except Exception as e:
            #If that fails write this as an exception
            helper.log_error("Error with writing event. Error Message:{}".format(e))

    elif response.status_code == 429:
        error_message = {"error" : "You have reached your API access limit.  Please contact Security Trails sales team"}
        json_data = json.dumps(error_message)
        helper.addevent(json_data, sourcetype="securitytrails:json")
        
        try:
            #Try writing to the specified index in global settings
            helper.writeevents(source="securitytrails", index=index_name, host="adaptive_response")
        except Exception as e:
            #If that fails write this as an exception
            helper.log_error("Error with writing event. Error Message:{}".format(e))
    
    else:        
        #If all fails then output an error message to the logging framework for passing onto security trails.
        helper.log_error("Error with request of {}, response code of {} and content of {}.  Please pass this information onto security trails if you believe this is incorrect.".format(value_search,response.status_code,response.json()))
    
    
 
    

    # TODO: Implement your alert action logic here
    return 0
