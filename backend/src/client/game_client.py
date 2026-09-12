from typing import List

import requests
from src.business_object.game import Game


def get_games() -> List[Game]:
    r = requests.get("http://localhost:5555")
    r.raise_for_status()
    json = r.json()
    rep = []
    for item in json:
        game = Game(item["player_list"][0], item["player_list"][1], item["mode_type"],
        item["winner_name"], item["location_name"], None, item["uuid_match"])
        rep.append(game)
    return rep

if __name__ == "__main__":
    games = get_games()
    print(f"{len(games)} games loaded:")
    for g in games:
        print
