import requests
import os
from dotenv import load_dotenv

load_dotenv()

tokenRequestUrl = "https://api-identity-infrastructure.nhncloudservice.com"
uri = "/v2.0/tokens"
tenantId= os.getenv("NHNCloud_tenantID")


body = {
    "auth": {
        "tenantId": tenantId,
        "passwordCredentials": {
            "username": os.getenv("NHNCloud_userID"),
            "password": os.getenv("NHNCloud_password")
        }
    }
}

response = requests.post(tokenRequestUrl + uri, json=body)
tokenId = response.json()["access"]["token"]["id"]

instanceRequestUrl = "https://kr1-api-instance-infrastructure.nhncloudservice.com"
instanceRequestUri = f"/v2/{tenantId}/servers"

header = {
    "X-Auth-Token": tokenId
}


keyUri = f"/v2/{tenantId}/os-keypairs"

#for i in range(1,6):
#    keyBody = {
#        "keypair": {
#            "name": f"junkey {i}",
#        }
#    }
#    response = requests.post(instanceRequestUrl + keyUri, json=keyBody, headers= header)
#    print(response)    

response = requests.get(instanceRequestUrl + keyUri, headers=header)
data = response.json()  

keyDeleteInput = input("삭제할 키페어 이름을 입력하세요 : ")
keyDeleteUri= f"/v2/{tenantId}/os-keypairs/{keyDeleteInput}"
response = requests.delete(instanceRequestUrl + keyDeleteUri, headers=header)




#for item in data["keypairs"]:
#    keypairName = item["keypair"]["name"]
#    keyDeleteUri= f"/v2/{tenantId}/os-keypairs/{keypairName}"
#    requests.delete(instanceRequestUrl + keyDeleteUri, headers=header)

