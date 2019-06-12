d = values = {
    frozenset(("action=add", "id=95")): {
        "status_code": "200",
        "text": {
            "responseData": {
                "accessKeyId": "XXXXXXXXXXXXXX",
                "creationDate": 1492034247291,
                "id": 76,
                "secretAccessKey": "AAAAAAAAAAAAAHHHHHHHHHHHHHHHHHHHNNNNNN",
            },
            "responseHeader": {
                "now": 1492034247299,
                "requestId": "WO6ixwoQgF4AAAZw1cQAAACo",
                "status": "ok",
            },
            "responseStatus": "ok",
        },
    },
    frozenset(("action=add", "id=14")): {
        "status_code": "404",
        "text": {
            "responseData": {
                "accessKeyId": "ZZZZZZZZZZZZZZZ",
                "creationDate": 1492034247291,
                "id": 76,
                "secretAccessKey": "AAAAAAAAAAAAAHHHHHHHHHHHHHHHHHHHNNNNNN",
            },
            "responseHeader": {
                "now": 1492034247299,
                "requestId": "WO6ixwoQgF4AAAZw1cQAAACo",
                "status": "ok",
            },
            "responseStatus": "ok",
        },
    },
    frozenset(("action=remove", "id=95", "accessKeyId=XXXXXXXXXXXXXX")): {
        "status_code": "200",
        "text": {
            "responseData": {},
            "responseHeader": {
                "now": 1492036702660,
                "requestId": "WO6sXgoQgF4AAAZw2B8AAACQ",
                "status": "ok",
            },
            "responseStatus": "ok",
        },
    },
    frozenset(("action=remove", "id=95", "accessKeyId=YYYYYYYYYYYYYYY")): {
        "status_code": "404",
        "text": "Error when retrieving the key",
    },
    frozenset(("action=remove", "id=12", "accessKeyId=YYYYYYYYYYYYYYY")): {
        "status_code": "404",
        "text": "Error when retrieving the key",
    },
}

if __name__ == "__main__":
    # print(d)
    print(d.keys())
    # print("")
    # print(d[frozenset(("action=add", "id=95"))])
    # print(d[frozenset(("id=95", "action=add"))])
