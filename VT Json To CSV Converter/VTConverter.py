# Convert Mandiant Json after reformatting to a CSV file using Python & Pandas
import json
import pandas
import os


def ReadJson(filename: str) -> dict:
    global data
    data = ""
    try:
        with open(filename, "r") as f:
            data = json.loads(f.read())
    except:
        print("error opening the JSON file")
    return data


def CreateDataFrame(data: list) -> pandas.DataFrame:
    dataframe = pandas.DataFrame()
    for d in data:
        row = pandas.json_normalize(d['data'])
        dataframe = dataframe.append(row)
    if "attributes.url" in dataframe and "attributes.registrar" in dataframe and "attributes.type_description" in dataframe and "attributes.regional_internet_registry" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.type_description": "Type"})
        dataframe = dataframe.rename(columns={"attributes.names": "Names"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.registrar": "Registrar"})
        dataframe = dataframe.rename(columns={"attributes.url": "Indicator URL"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Type', 'Names', 'Tags', 'Malicious', 'Suspicious',
                     'Registrar', 'Indicator URL']]
    elif "attributes.url" in dataframe and "attributes.registrar" in dataframe and "attributes.type_description" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.type_description": "Type"})
        dataframe = dataframe.rename(columns={"attributes.names": "Names"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.registrar": "Registrar"})
        dataframe = dataframe.rename(columns={"attributes.url": "Indicator URL"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Type', 'Names', 'Tags', 'Malicious', 'Suspicious',
                     'Registrar', 'Indicator URL']]
    elif "attributes.url" in dataframe and "attributes.regional_internet_registry" in dataframe and "attributes.type_description" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.type_description": "Type"})
        dataframe = dataframe.rename(columns={"attributes.names": "Names"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.url": "Indicator URL"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Type', 'Names', 'Tags', 'Malicious', 'Suspicious',
                     'Indicator URL']]
    elif "attributes.registrar" in dataframe and "attributes.regional_internet_registry" in dataframe and "attributes.type_description" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.type_description": "Type"})
        dataframe = dataframe.rename(columns={"attributes.names": "Names"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.registrar": "Registrar"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Type', 'Names', 'Tags', 'Malicious', 'Suspicious', 'Registrar']]
    elif "attributes.registrar" in dataframe and "attributes.type_description" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.type_description": "Type"})
        dataframe = dataframe.rename(columns={"attributes.names": "Names"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.registrar": "Registrar"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Type', 'Names', 'Tags', 'Malicious', 'Suspicious', 'Registrar']]
    elif "attributes.url" in dataframe and "attributes.registrar" in dataframe:
        print("on attributes.url and attributes.registrar")
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.registrar": "Registrar"})
        dataframe = dataframe.rename(columns={"attributes.url": "Indicator URL"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Tags', 'Malicious', 'Suspicious', 'Registrar',
                     'Indicator URL']]
    elif "attributes.url" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.url": "Indicator URL"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Tags', 'Malicious', 'Suspicious', 'Indicator URL']]
    elif "attributes.registrar" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.registrar": "Registrar"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Tags', 'Malicious', 'Suspicious', 'Registrar']]
    elif "attributes.type_description" in dataframe:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.type_description": "Type"})
        dataframe = dataframe.rename(columns={"attributes.names": "Names"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.rename(columns={"attributes.registrar": "Registrar"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Type', 'Names', 'Tags', 'Malicious', 'Suspicious']]
    else:
        dataframe = dataframe.rename(columns={"type": "Indicator Type"})
        dataframe = dataframe.rename(columns={"id": "Indicator Value"})
        dataframe = dataframe.rename(columns={"attributes.tags": "Tags"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.malicious": "Malicious"})
        dataframe = dataframe.rename(columns={"attributes.last_analysis_stats.suspicious": "Suspicious"})
        dataframe = dataframe.loc[:,
                    ['Indicator Type', 'Indicator Value', 'Tags', 'Malicious', 'Suspicious']]
    return dataframe


def ReformateJsonFile(file):
    global data
    if os.path.exists(file):
        print("Json file found and conversion process started")
        with open(file, "r") as r:
            response = r.read()
            response = response.replace('\n', '')
            response = response.replace('}{', '},{')
            response = '{"AllResults": [' + response + ']}'
            print(response, file=open("VTFormatted.json", "w"))
        data = ReadJson(filename="VTFormatted.json")
        dataframe = CreateDataFrame(data=data['AllResults'])
        dataframe.to_csv("VT Result.csv", index=False)
        print("Json file has been converted successfully to CSV")
    else:
        print("Please, make sure that you have a file named 'VirusTotal Json Result.json' in the same path")
        exit()

def ConvertToCSV():
    ReformateJsonFile("VirusTotal Json Result.json")


ConvertToCSV()
