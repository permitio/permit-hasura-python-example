# Permit-Hasura Python example

Builds on the [Hasura Python example](https://hasura.io/docs/latest/graphql/core/actions/codegen/python-flask/) adding application level permission checks with Permit.

This example assumes an additional text field on the `user` table (mentioned in the Hasura example): `animal`

## Setup and Run

- Follow in the instructions in [Hasura Python example](https://hasura.io/docs/latest/graphql/core/actions/codegen/python-flask/) to setup your Hasura actions and underlying table.
- Setup your [Permit account](https://app.permit.io) and [PDP](https://docs.permit.io/tutorials/quickstart)
- Update secrets for Permit and Hasura in app.py constants
- Install requirements : `pip install -r requirements.txt`
- Use the code provided in app.py as the final result
- run the app : `python app.py`
- [Optional] Test the app with the util.py client : `python util.py`
  - create a user `python util.py create-user "user@test.com" "Pass123"`
  - login and list animals as user `python util.py list-animals "user@test.com" "Pass123"`

## Highlights and differences from the Hasura example

- Added email to the JWT (to be used as the user id)
- added a few requirements to requirements.txt
- Added a `animal` field to the `user` table
- Added a new feature to list all the users with their animals

- Added a call to `permit.sync_user()` as part of the sign-up route

  ```python
  # Let Permit know of the new user
  # We'll use the email as our unique identifier (in Prod a UUID would be better)
  user["key"] = user["email"]
  # Assign a default basic role
  user["roles"] = [{"role":"admin", "tenant": "default"}]
  userInput = UserInput(**user)
  # Save to permit
  permit.write(permit.api.sync_user(userInput))
  ```

- Added an enforcement point with permit to control who can list animals (fully controlled from Permit's policy-editor in realtime)
  ```python
   # enforce app-level access with Permit
  if permit.check(id, "list", "animals"):
      user_response = client.list_animals()
      return jsonify(user_response["data"]["user"])
  else:
      return make_response(jsonify({
          'message': 'Not allowed'
      } )), 403
  ```
