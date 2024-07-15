import azure.functions as func
import logging

import requests

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)
@app.route(route="http_trigger_poc")
def http_trigger_poc(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    url = "https://ingest.us-1.crowdstrike.com/api/ingest/hec/be05febd4f9f49809f094cec369f92c7/v1/services/collector"

    payload = {"event": {
            "time": "2024-07-15T05:08:09Z",
            "systemId": "2ed3d102-f60d-49cb-91f1-3e26d8e13d1f",
            "macAddress": "6045BD72AEC4",
            "category": "NetworkSecurityGroupFlowEvent",
            "resourceId": "/SUBSCRIPTIONS/8828C958-EEA2-4E76-967D-B25F04D93A33/RESOURCEGROUPS/NSGFLOWGRP/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/NSGVM-NSG",
            "operationName": "NetworkSecurityGroupFlowEvents",
            "properties": {
                "Version": 2,
                "flows": [
                    {
                        "rule": "DefaultRule_AllowInternetOutBound",
                        "flows": [
                            {
                                "mac": "6045BD72AEC4",
                                "flowTuples": ["1718783992,10.0.0.4,52.140.118.28,52237,443,T,O,A,B,,,,", "1718783993,10.0.0.4,52.140.118.28,52238,443,T,O,A,B,,,,", "1718783997,10.0.0.4,52.140.118.28,52237,443,T,O,A,C,10,1736,10,4963", "1718783997,10.0.0.4,52.140.118.28,52238,443,T,O,A,C,2,468,12,5118", "1718783997,10.0.0.4,52.140.118.28,52237,443,T,O,A,E,0,0,0,0", "1718783998,10.0.0.4,52.140.118.28,52238,443,T,O,A,E,0,0,0,0"]
                            }
                        ]
                    },
                    {
                        "rule": "DefaultRule_DenyAllInBound",
                        "flows": [
                            {
                                "mac": "6045BD72AEC4",
                                "flowTuples": ["1718783982,65.49.1.23,10.0.0.4,56332,7443,T,I,D,B,,,,", "1718783984,94.156.71.19,10.0.0.4,43736,27017,T,I,D,B,,,,", "1718783990,147.185.133.136,10.0.0.4,50079,9506,T,I,D,B,,,,", "1718783994,35.203.211.96,10.0.0.4,55464,18383,T,I,D,B,,,,", "1718784005,35.203.210.195,10.0.0.4,56415,9774,T,I,D,B,,,,", "1718784009,62.122.184.64,10.0.0.4,58904,9803,T,I,D,B,,,,", "1718784012,172.233.17.82,10.0.0.4,55662,4242,T,I,D,B,,,,", "1718784016,79.110.62.61,10.0.0.4,55120,61753,T,I,D,B,,,,", "1718784016,165.255.107.230,10.0.0.4,61305,80,T,I,D,B,,,,", "1718784016,35.203.210.141,10.0.0.4,54034,8040,T,I,D,B,,,,", "1718784030,185.191.127.212,10.0.0.4,51728,80,T,I,D,B,,,,"]
                            }
                        ]
                    },
                    {
                        "rule": "UserRule_RDP",
                        "flows": [
                            {
                                "mac": "6045BD72AEC4",
                                "flowTuples": ["1718783979,152.89.198.238,10.0.0.4,60609,3389,T,I,A,B,,,,", "1718783987,152.89.198.238,10.0.0.4,50741,3389,T,I,A,B,,,,", "1718783994,152.89.198.238,10.0.0.4,58256,3389,T,I,A,B,,,,", "1718784001,152.89.198.238,10.0.0.4,65149,3389,T,I,A,B,,,,", "1718784008,152.89.198.238,10.0.0.4,55097,3389,T,I,A,B,,,,", "1718784016,152.89.198.238,10.0.0.4,60763,3389,T,I,A,B,,,,", "1718784023,152.89.198.238,10.0.0.4,54611,3389,T,I,A,B,,,,", "1718784031,152.89.198.238,10.0.0.4,62516,3389,T,I,A,B,,,,"]
                            }
                        ]
                    }
                ]
            }
        }}
    headers = {
        "Authorization": "Bearer 2f88e67c4a89429284d259fe97ff9a1a",
        "Content-Type": "application/json"
    }

    response = requests.request("POST", url, json=payload, headers=headers)
    if response.status_code == 201 or response.status_code==200:  # Assuming 201 Created is the success status code
        print(response.text)
        return func.HttpResponse(f"Success: {response.text}", status_code=201)
    else:
        return func.HttpResponse(f"Failed: {response.text}", status_code=response.status_code)
