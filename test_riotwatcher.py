import requests

# Clé API fournie
api_key = "RGAPI-d2a25856-b461-48fb-a0e3-101cf599efd6"

# PUUID obtenu précédemment
puuid = "ZlkZp60c_I9ctxnvp2hRf7kPnaqcMdFLdgDPSfxi37Vn9mKyzp2Wqf9CjfsNNiijgIdSNoTICEIvsA"
region = "euw1"  # Région du serveur pour l'invocateur

# URL de l'API pour obtenir les informations de l'invocateur
summoner_url = f"https://{region}.api.riotgames.com/lol/summoner/v4/summoners/by-puuid/{puuid}"
headers = {"X-Riot-Token": api_key}

print(f"Requête à l'URL: {summoner_url}")
print(f"En-têtes: {headers}")

# Effectuer la requête pour obtenir les informations de l'invocateur
summoner_response = requests.get(summoner_url, headers=headers)

if summoner_response.status_code == 200:
    summoner_data = summoner_response.json()
    print("Informations de l'invocateur :", summoner_data)
else:
    print(f"Erreur {summoner_response.status_code}: {summoner_response.json()}")
