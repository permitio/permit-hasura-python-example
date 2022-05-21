import requests
import typer

app = typer.Typer()

@app.command()
def create_user(email:str, password:str):
    request = requests.post(
        "http://localhost:8080/signup", json={"input":{"email": email, "password": password}})
    assert request.ok, f"Failed with code {request.status_code}"
    print (request.json())


@app.command()
def login(email:str, password:str):
    request = requests.post(
        "http://localhost:8080/login", json={"input":{"email": email, "password": password}})
    assert request.ok, f"Failed with code {request.status_code}"
    return request.json()


@app.command()
def list_animals(email:str, password:str):
    token = login(email, password)
    request = requests.get(
        "http://localhost:8080/animals", json={"input":{"email": email, "password": password}}, headers={"Authorization": f"Bearer {token['token']}"})
    assert request.ok, f"Failed with code {request.status_code}"
    print (request.json())



if __name__ == "__main__":
    app()
