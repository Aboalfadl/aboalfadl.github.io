import requests
import json
import time
import pandas
import os
import shutil
from itertools import islice

################################################################################
# This tool is designed and coded by Fadl0X Aka Dark to help the blue teams    #
# while doing their job to fast analysis indicators whatever the type of       # 
# indicator by implementing A multi search function using mandiant APIs        #
# (Of course) if your employer already subscribe to mandiant threat intel.     #
# the tool will search on all the indicators you provide against mandiant APIs # 
# and will return with the result in a CSV formate to be easy readable         #
################################################################################

###############################################################TOOL BANNER###############################################################
print("ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo")
print("___  ___                _ _             _     _____          _ _           _               _____                                 ")
print("|  \/  |               | (_)           | |   |_   _|        | (_)         | |             /  ___|                                ")
print("| .  . | __ _ _ __   __| |_  __ _ _ __ | |_    | | _ __   __| |_  ___ __ _| |_ ___  _ __  \ `--.  ___ __ _ _ __  _ __   ___ _ __ ")
print("| |\/| |/ _` | '_ \ / _` | |/ _` | '_ \| __|   | || '_ \ / _` | |/ __/ _` | __/ _ \| '__|  `--. \/ __/ _` | '_ \| '_ \ / _ \ '__|")
print("| |  | | (_| | | | | (_| | | (_| | | | | |_   _| || | | | (_| | | (_| (_| | || (_) | |    /\__/ / (_| (_| | | | | | | |  __/ |   ")
print("\_|  |_/\__,_|_| |_|\__,_|_|\__,_|_| |_|\__|  \___/_| |_|\__,_|_|\___\__,_|\__\___/|_|    \____/ \___\__,_|_| |_|_| |_|\___|_|   ")
print("ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo")
###############################################################TOOL BANNER###############################################################



TokenAPIURL = 'https://api.intelligence.fireeye.com/token'
Payload = {"grant_type": "client_credentials", "scope": "read"}

global count
global DatabasePath; DatabasePath = 'database'

def ReadKeys():
    if os.path.exists("keys.txt"):
        print("Reading your keys...")
        APIKeys = open("keys.txt","r")
        Values = list(APIKeys.readlines())
        Client_ID = Values[0].strip()
        Client_Secret = Values[1].strip()
        print("Keys have been loaded successfully")
        print("ID:",Client_ID.replace("\n",""))
        print("Secret:", Client_Secret)
        time.sleep(1)
        LoginToMandiantAPI(Client_ID, Client_Secret)
    else:
        print("Error, please make sure that your keys are exists in keys.txt in the same folder")
        time.sleep(1)
        exit()


def LoginToMandiantAPI(Client_ID,Client_Secret):
    global APIAuthToken, count
    if os.path.exists("indicators.txt"):
        count = IndicatorsCount()
    else:
        print("Error, please place the indicators file in the same folder and try again.")
        exit()
    print("Start Authetication...")
    time.sleep(1)
    TokenRequest = requests.post(TokenAPIURL, data=Payload, auth=(Client_ID, Client_Secret))
    if TokenRequest.status_code == 200:
        APIAuthToken = TokenRequest.json()["access_token"]
        print("Successfully Authenticated")
        time.sleep(1)
    else:
        print("Authentication failed, Please check your keys")
        exit()
    time.sleep(1)
    if os.path.exists("searchresult.json"):
        os.remove("searchresult.json")

    print("Loading Indicators...")
    CreateDatabase()
    print(count,"indicators loaded...")
    print("Sending indicators to API...")
    Search(APIAuthToken,count)



def Search(APIAuthToken,count):
    
    StartTime = time.time()
    for filename in os.listdir(DatabasePath):
        Indicators = LoadIndicators(filename)
        url = "https://api.intelligence.fireeye.com/v4/indicator"
        payload = json.dumps({"limit": 100, "offset": 0, "requests": [{"values": Indicators}]})
        headers = {'Accept': 'application/json','Content-Type': 'application/json','Authorization': 'Bearer ' + APIAuthToken}
        ManRequest = requests.request("POST", url, headers=headers, data=payload)
        if ManRequest.status_code == 200 and ManRequest.text != '':
            print(ManRequest.text, file=open("searchresult.json", "a"))
            print(filename, "processed successfully.")
        else:
            print(filename, "has empty results or invalid indicators")
    print(count, "indicators result now saved in searchresult.json file")
    ConvertToCSV()
    time.sleep(1)
    RemoveWorkingFiles()
    EndTime = time.time()
    ElaspsidTime = EndTime - StartTime
    print("Search process took:", ElaspsidTime)

def IndicatorsCount():
    file = open("indicators.txt","r")
    Counter = 0
    Content = file.read()
    CoList = Content.split("\n")
    for i in CoList:
        if i:
            Counter += 1         
    return Counter

def LoadIndicators(filename):
    filepath = os.path.join(DatabasePath, filename)
    indicatorsfile = open(filepath, "r")
    lines = indicatorsfile.read()
    lines = lines.replace('\n', ',')
    li = list(lines.split(","))
    return li


def CreateDatabase():
    isExist = os.path.exists(DatabasePath)
    if isExist:
        shutil.rmtree(DatabasePath)
        os.makedirs(DatabasePath)
    if not isExist:
        os.makedirs(DatabasePath)

    with open('indicators.txt') as indicatorsfile:
        for i, sli in enumerate(iter(lambda:list(islice(indicatorsfile, 96)), []), 1):
            with open(f"database/indicators{i:03}", "w") as f:
                f.writelines(sli)


def ReadJson(filename: str) -> dict:
    global data; data = ""
    try:
        with open(filename, "r") as f:
            data = json.loads(f.read())
    except:
        print("error opening the JSON file")

    return data


def CreateDataFrame(data: list) -> pandas.DataFrame:
    dataframe = pandas.DataFrame()

    for d in data:
        record = pandas.json_normalize(d['indicators'])
        dataframe = dataframe.append(record, ignore_index=True)
    if "attributed_associations" in dataframe:
        if "associated_hashes" in dataframe:
            dataframe = dataframe.rename(columns={"value": "Indicator Value"})
            dataframe = dataframe.rename(columns={"type": "Indicator Type"})
            dataframe = dataframe.rename(columns={"mscore": "Score"})
            dataframe = dataframe.rename(columns={"attributed_associations": "Associations"})
            dataframe = dataframe.rename(columns={"associated_hashes": "Associated Hashes"})
            dataframe = dataframe.rename(columns={"first_seen": "First Seen"})
            dataframe = dataframe.rename(columns={"last_seen": "Last Seen"})
            dataframe = dataframe.rename(columns={"last_updated": "Last Updated"})
            dataframe = dataframe.loc[:, ['Indicator Value', 'Indicator Type','Score','Associations','Associated Hashes','First Seen','Last Seen','Last Updated']]
        else:
            dataframe = dataframe.rename(columns={"value": "Indicator Value"})
            dataframe = dataframe.rename(columns={"type": "Indicator Type"})
            dataframe = dataframe.rename(columns={"mscore": "Score"})
            dataframe = dataframe.rename(columns={"attributed_associations": "Associations"})
            dataframe = dataframe.rename(columns={"first_seen": "First Seen"})
            dataframe = dataframe.rename(columns={"last_seen": "Last Seen"})
            dataframe = dataframe.rename(columns={"last_updated": "Last Updated"})
            dataframe = dataframe.loc[:, ['Indicator Value', 'Indicator Type','Score','Associations','First Seen','Last Seen','Last Updated']]  
    else:
        dataframe = dataframe.rename(columns={"value": "Indicator Value"})
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"mscore": "Score"})
        dataframe = dataframe.rename(columns={"first_seen": "First Seen"})
        dataframe = dataframe.rename(columns={"last_seen": "Last Seen"})
        dataframe = dataframe.rename(columns={"last_updated": "Last Updated"})
        dataframe = dataframe.loc[:, ['Indicator Value', 'Indicator Type','Score','First Seen','Last Seen','Last Updated']]
    
    return dataframe

def ReformateJsonFile(file):
    global data
    with open(file, "r") as r:
        response = r.read()
        response = response.replace('{"error": "Wildcards not supported on this request!"}','')
        response = response.replace('\n', '')
        response = response.replace('}{', '},{')
        response = '{"AllResults": [' + response + ']}'
        print(response, file=open("formatted.json", "w"))
    data = ReadJson(filename="formatted.json")
    dataframe = CreateDataFrame(data=data['AllResults'])
    dataframe.to_csv("searchresult.csv", index=False)
    print("Json file has been converted successfully to CSV: searchresult.csv")

def ConvertToCSV():
    if os.path.exists("searchresult.csv"):
        os.remove("searchresult.csv")
    ReformateJsonFile("searchresult.json")

def RemoveWorkingFiles():
    if os.path.exists("searchresult.json"):
        os.remove("searchresult.json")
    if os.path.exists("formatted.json"):
        os.remove("formatted.json")
    shutil.rmtree(DatabasePath)          

ReadKeys()