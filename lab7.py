import hashlib
import requests
def getFileSha256(file_path):
    with open(file_path, "rb") as file:
        return hashlib.sha256(file.read()).hexdigest()

def getFileInfo(file_path, password = None):
    api_url = 'https://www.virustotal.com/api/v3/files'
    api_key = '3871f0b3502483801adeb6bc870d0ec78c132fcd6321fc9990495a5296735411'
    headers = {'x-apikey' : api_key}
    payload = {}
    if password is not None:
        payload = {'password' : password}
    with open(file_path, "rb") as file:
        files = {'file' : (file_path, file)}
        response = requests.post(api_url, data=payload, headers=headers, files=files)
        if response.status_code == 200:
            fileIdentifier = getFileSha256(file_path)
            url = f'https://www.virustotal.com/api/v3/files/{fileIdentifier}'
            response = requests.get(url, headers=headers)
            return response.json()
    return None

if __name__ == '__main__':
    file_path = 'image.png'
    file_info = getFileInfo(file_path)
    if file_info is None:
        print('An error occured')
    else:
        print(file_info)
        print(file_info['data']['attributes']['last_analysis_stats'])

    file_path = 'SSI_L7_sample1.zip'
    file_info = getFileInfo(file_path, 'infected')
    if file_info is None:
        print('An error occured')
    else:
        print(file_info)
        print(file_info['data']['attributes']['last_analysis_stats'])


